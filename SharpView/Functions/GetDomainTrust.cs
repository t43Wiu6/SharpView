using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.Xml;
using System.Runtime.InteropServices;
using System.DirectoryServices.ActiveDirectory;
using SharpView.Arguments;
using SharpView.Returns;
using SharpView.Enums;
using SharpView.Utils;
using SharpView.Interfaces;
using System.Diagnostics.Eventing.Reader;
using static SharpView.Utils.NativeMethods;
using System.Security.AccessControl;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Text;
using System.Security.Principal;
using SharpView.Functions;

namespace SharpView.Functions
{ 
    class GetDomainTrust
    { 
        public static IEnumerable<IDomainTrust> Get_DomainTrust(Args_Get_DomainTrust args = null)
        {
            if (args == null) args = new Args_Get_DomainTrust();

            var LdapSearcherArguments = new Args_Get_DomainSearcher
            {
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            Args_Get_DomainSID NetSearcherArguments = null;
            string SourceDomain = null;
            if (!args.API)
            {
                NetSearcherArguments = new Args_Get_DomainSID();
                if (args.Domain.IsNotNullOrEmpty() && args.Domain.Trim() != "")
                {
                    SourceDomain = args.Domain;
                }
                else
                {
                    if (args.Credential != null)
                    {
                        SourceDomain = GetDomain.Get_Domain(new Args_Get_Domain { Credential = args.Credential }).Name;
                    }
                    else
                    {
                        SourceDomain = GetDomain.Get_Domain().Name;
                    }
                }
            }
            else if (!args.NET)
            {
                if (args.Domain != null && args.Domain.Trim() != "")
                {
                    SourceDomain = args.Domain;
                }
                else
                {
                    SourceDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                }
            }

            var DomainTrusts = new List<IDomainTrust>();
            if (!args.API && !args.NET)
            {
                // if we're searching for domain trusts through LDAP/ADSI
                var TrustSearcher = GetDomainSearcher.Get_DomainSearcher(LdapSearcherArguments);
                var SourceSID = GetDomainSID.Get_DomainSID(NetSearcherArguments);

                if (TrustSearcher != null)
                {
                    TrustSearcher.Filter = @"(objectClass=trustedDomain)";

                    SearchResult[] Results = null;
                    if (args.FindOne) { Results = new SearchResult[] { TrustSearcher.FindOne() }; }
                    else
                    {
                        var items = TrustSearcher.FindAll();
                        if (items != null)
                        {
                            Results = new SearchResult[items.Count];
                            items.CopyTo(Results, 0);
                        }
                    }
                    if (Results != null)
                    {
                        foreach (var result in Results)
                        {
                            var Props = result.Properties;
                            var DomainTrust = new LdapDomainTrust();

                            var TrustAttrib = (TrustAttribute)Props[@"trustattributes"][0];

                            var Direction = (TrustDirection)Props[@"trustdirection"][0];

                            var TrustType = (TrustType)Props[@"trusttype"][0];

                            var Distinguishedname = Props[@"distinguishedname"][0] as string;
                            var SourceNameIndex = Distinguishedname.IndexOf(@"DC=");
                            if (SourceNameIndex != 0)
                            {
                                SourceDomain = Distinguishedname.Substring(SourceNameIndex).Replace(@"DC=", @"").Replace(@",", @".");
                            }
                            else
                            {
                                SourceDomain = @"";
                            }

                            var TargetNameIndex = Distinguishedname.IndexOf(@",CN=System");
                            string TargetDomain = null;
                            if (SourceNameIndex != 0)
                            {
                                TargetDomain = Distinguishedname.Substring(3, TargetNameIndex - 3);
                            }
                            else
                            {
                                TargetDomain = @"";
                            }

                            var ObjectGuid = new Guid(Props[@"objectguid"][0] as byte[]);
                            var TargetSID = (new System.Security.Principal.SecurityIdentifier(Props[@"securityidentifier"][0] as byte[], 0)).Value;

                            DomainTrust = new LdapDomainTrust
                            {
                                SourceName = SourceDomain,
                                TargetName = Props[@"name"][0] as string,
                                TrustType = TrustType,
                                TrustAttributes = TrustAttrib,
                                TrustDirection = Direction,
                                WhenCreated = Props[@"whencreated"][0],
                                WhenChanged = Props[@"whenchanged"][0]
                            };
                            DomainTrusts.Add(DomainTrust);
                        }
                    }
                    TrustSearcher.Dispose();
                }
            }
            else if (args.API)
            {
                // if we're searching for domain trusts through Win32 API functions
                string TargetDC = null;
                if (args.Server.IsNotNullOrEmpty())
                {
                    TargetDC = args.Server;
                }
                else if (args.Domain != null && args.Domain.Trim() != @"")
                {
                    TargetDC = args.Domain;
                }
                else
                {
                    // see https://msdn.microsoft.com/en-us/library/ms675976(v=vs.85).aspx for default NULL behavior
                    TargetDC = null;
                }

                // arguments for DsEnumerateDomainTrusts
                var PtrInfo = IntPtr.Zero;

                // 63 = DS_DOMAIN_IN_FOREST + DS_DOMAIN_DIRECT_OUTBOUND + DS_DOMAIN_TREE_ROOT + DS_DOMAIN_PRIMARY + DS_DOMAIN_NATIVE_MODE + DS_DOMAIN_DIRECT_INBOUND
                uint Flags = 63;
                uint DomainCount = 0;

                // get the trust information from the target server
                var Result = NativeMethods.DsEnumerateDomainTrusts(TargetDC, Flags, out PtrInfo, out DomainCount);

                // Locate the offset of the initial intPtr
                var Offset = PtrInfo.ToInt64();

                // 0 = success
                if (Result == 0 && Offset > 0)
                {
                    // Work out how much to increment the pointer by finding out the size of the structure
                    var Increment = Marshal.SizeOf(typeof(NativeMethods.DS_DOMAIN_TRUSTS));

                    // parse all the result structures
                    for (var i = 0; i < DomainCount; i++)
                    {
                        // create a new int ptr at the given offset and cast the pointer as our result structure
                        var NewIntPtr = new IntPtr(Offset);
                        var Info = (NativeMethods.DS_DOMAIN_TRUSTS)Marshal.PtrToStructure(NewIntPtr, typeof(NativeMethods.DS_DOMAIN_TRUSTS));

                        Offset = NewIntPtr.ToInt64();
                        Offset += Increment;

                        var SidString = @"";
                        bool ret = NativeMethods.ConvertSidToStringSid(Info.DomainSid, out SidString);
                        var LastError = Marshal.GetLastWin32Error();

                        if (ret == false)
                        {
                            Logger.Write_Verbose($@"[Get-DomainTrust] Error: {new System.ComponentModel.Win32Exception(LastError).Message}");
                        }
                        else
                        {
                            var DomainTrust = new ApiDomainTrust
                            {
                                SourceName = SourceDomain,
                                TargetName = Info.DnsDomainName,
                                TargetNetbiosName = Info.NetbiosDomainName,
                                Flags = Info.Flags,
                                ParentIndex = Info.ParentIndex,
                                TrustType = (NativeMethods.DS_DOMAIN_TRUST_TYPE)Info.TrustType,
                                TrustAttributes = Info.TrustAttributes,
                                TargetSid = SidString,
                                TargetGuid = Info.DomainGuid
                            };
                            DomainTrusts.Add(DomainTrust);
                        }
                    }
                    // free up the result buffer
                    NativeMethods.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-DomainTrust] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }
            else
            {
                // if we're searching for domain trusts through .NET methods
                var FoundDomain = GetDomain.Get_Domain(new Args_Get_Domain
                {
                    Domain = NetSearcherArguments.Domain,
                    Credential = NetSearcherArguments.Credential
                });
                if (FoundDomain != null)
                {
                    var items = FoundDomain.GetAllTrustRelationships();
                    foreach (TrustRelationshipInformation item in items)
                    {
                        DomainTrusts.Add(new NetDomainTrust
                        {
                            SourceName = item.SourceName,
                            TargetName = item.TargetName,
                            TrustDirection = item.TrustDirection,
                            TrustType = item.TrustType
                        });
                    }
                }
            }
            return DomainTrusts;
        }

    }
}
