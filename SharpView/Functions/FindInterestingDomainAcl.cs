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
    class FindInterestingDomainAcl
    { 
        public static IEnumerable<ACL> Find_InterestingDomainAcl(Args_Find_InterestingDomainAcl args = null)
        {
            if (args == null) args = new Args_Find_InterestingDomainAcl();

            var ACLArguments = new Args_Get_DomainObjectAcl
            {
                ResolveGUIDs = args.ResolveGUIDs,
                RightsFilter = args.RightsFilter,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ObjectSearcherArguments = new Args_Get_DomainObject
            {
                Properties = new[] { "samaccountname", "objectclass" },
                Raw = true,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ADNameArguments = new Args_Convert_ADName
            {
                Server = args.Server,
                Credential = args.Credential
            };

            // ongoing list of built-up SIDs
            var ResolvedSIDs = new Dictionary<string, ResolvedSID>();

            if (args.Domain != null)
            {
                ACLArguments.Domain = args.Domain;
                ADNameArguments.Domain = args.Domain;
            }

            var InterestingACLs = new List<ACL>();
            var acls = GetDomainObjectAcl.Get_DomainObjectAcl(ACLArguments);
            foreach (var acl in acls)
            {
                if ((acl.ActiveDirectoryRights.ToString().IsRegexMatch(@"GenericAll|Write|Create|Delete")) || ((acl.ActiveDirectoryRights == ActiveDirectoryRights.ExtendedRight) && (acl.Ace is QualifiedAce) && (acl.Ace as QualifiedAce).AceQualifier == AceQualifier.AccessAllowed))
                {
                    // only process SIDs > 1000
                    var ace = acl.Ace as QualifiedAce;
                    if (ace != null && ace.SecurityIdentifier.Value.IsRegexMatch(@"^S-1-5-.*-[1-9]\d{3,}$"))
                    {
                        if (ResolvedSIDs.ContainsKey(ace.SecurityIdentifier.Value) && ResolvedSIDs[ace.SecurityIdentifier.Value] != null)
                        {
                            var ResolvedSID = ResolvedSIDs[(acl.Ace as KnownAce).SecurityIdentifier.Value];
                            var InterestingACL = new ACL
                            {
                                ObjectDN = acl.ObjectDN,
                                Ace = ace,
                                ActiveDirectoryRights = acl.ActiveDirectoryRights,
                                IdentityReferenceName = ResolvedSID.IdentityReferenceName,
                                IdentityReferenceDomain = ResolvedSID.IdentityReferenceDomain,
                                IdentityReferenceDN = ResolvedSID.IdentityReferenceDN,
                                IdentityReferenceClass = ResolvedSID.IdentityReferenceClass
                            };
                            InterestingACLs.Add(InterestingACL);
                        }
                        else
                        {
                            ADNameArguments.Identity = new string[] { ace.SecurityIdentifier.Value };
                            ADNameArguments.OutputType = ADSNameType.DN;
                            var IdentityReferenceDN = ConvertADName.Convert_ADName(ADNameArguments)?.FirstOrDefault();
                            // "IdentityReferenceDN: $IdentityReferenceDN"

                            if (IdentityReferenceDN != null)
                            {
                                var IdentityReferenceDomain = IdentityReferenceDN.Substring(IdentityReferenceDN.IndexOf("DC=")).Replace(@"DC=", "").Replace(",", ".");
                                // "IdentityReferenceDomain: $IdentityReferenceDomain"
                                ObjectSearcherArguments.Domain = IdentityReferenceDomain;
                                ObjectSearcherArguments.Identity = new[] { IdentityReferenceDN };
                                // "IdentityReferenceDN: $IdentityReferenceDN"
                                var Object = GetDomainObject.Get_DomainObject(ObjectSearcherArguments)?.FirstOrDefault() as SearchResult;

                                if (Object != null)
                                {
                                    var IdentityReferenceName = Object.Properties["samaccountname"][0].ToString();
                                    string IdentityReferenceClass;
                                    if (Object.Properties["objectclass"][0].ToString().IsRegexMatch(@"computer"))
                                    {
                                        IdentityReferenceClass = "computer";
                                    }
                                    else if (Object.Properties["objectclass"][0].ToString().IsRegexMatch(@"group"))
                                    {
                                        IdentityReferenceClass = "group";
                                    }
                                    else if (Object.Properties["objectclass"][0].ToString().IsRegexMatch(@"user"))
                                    {
                                        IdentityReferenceClass = "user";
                                    }
                                    else
                                    {
                                        IdentityReferenceClass = null;
                                    }

                                    // save so we don't look up more than once
                                    ResolvedSIDs[ace.SecurityIdentifier.Value] = new ResolvedSID
                                    {
                                        IdentityReferenceName = IdentityReferenceName,
                                        IdentityReferenceDomain = IdentityReferenceDomain,
                                        IdentityReferenceDN = IdentityReferenceDN,
                                        IdentityReferenceClass = IdentityReferenceClass
                                    };

                                    var InterestingACL = new ACL
                                    {
                                        ObjectDN = acl.ObjectDN,
                                        Ace = ace,
                                        ActiveDirectoryRights = acl.ActiveDirectoryRights,
                                        IdentityReferenceName = IdentityReferenceName,
                                        IdentityReferenceDomain = IdentityReferenceDomain,
                                        IdentityReferenceDN = IdentityReferenceDN,
                                        IdentityReferenceClass = IdentityReferenceClass
                                    };
                                    InterestingACLs.Add(InterestingACL);
                                }
                            }
                            else
                            {
                                Logger.Write_Warning($@"[Find-InterestingDomainAcl] Unable to convert SID '{ace.SecurityIdentifier.Value}' to a distinguishedname with Convert-ADName");
                            }
                        }
                    }
                }
            }

            return InterestingACLs;
        }

    }
}
