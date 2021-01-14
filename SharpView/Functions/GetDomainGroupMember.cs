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
    class GetDomainGroupMember
    { 
        public static IEnumerable<GroupMember> Get_DomainGroupMember(Args_Get_DomainGroupMember args = null)
        {
            if (args == null) args = new Args_Get_DomainGroupMember();

            var SearcherArguments = new Args_Get_DomainSearcher()
            {
                Properties = new string[] { @"member", @"samaccountname", @"distinguishedname" },
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ADNameArguments = new Args_Convert_ADName
            {
                Domain = args.Domain,
                Server = args.Server,
                Credential = args.Credential
            };

            var GroupMembers = new List<GroupMember>();
            var GroupSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
            if (GroupSearcher != null)
            {
                string GroupFoundDomain = null;
                string GroupFoundName = null;
                string GroupFoundDN = null;
                List<string> Members = null;
                if (args.RecurseUsingMatchingRule)
                {
                    var GroupArguments = new Args_Get_DomainGroup()
                    {
                        Properties = SearcherArguments.Properties,
                        Domain = SearcherArguments.Domain,
                        LDAPFilter = SearcherArguments.LDAPFilter,
                        SearchBase = SearcherArguments.SearchBase,
                        Server = SearcherArguments.Server,
                        SearchScope = SearcherArguments.SearchScope,
                        ResultPageSize = SearcherArguments.ResultPageSize,
                        ServerTimeLimit = SearcherArguments.ServerTimeLimit,
                        Tombstone = SearcherArguments.Tombstone,
                        Credential = SearcherArguments.Credential,
                        Identity = args.Identity,
                        Raw = true
                    };
                    var Groups = GetDomainGroup.Get_DomainGroup(GroupArguments);

                    if (Groups == null)
                    {
                        Logger.Write_Warning($@"[Get-DomainGroupMember] Error searching for group with identity: {args.Identity}");
                    }
                    else
                    {
                        var Group = Groups.First() as SearchResult;
                        GroupFoundName = Group.Properties[@"samaccountname"][0] as string;
                        GroupFoundDN = Group.Properties[@"distinguishedname"][0] as string;
                        if (args.Domain.IsNotNullOrEmpty())
                        {
                            GroupFoundDomain = args.Domain;
                        }
                        else
                        {
                            // if a domain isn't passed, try to extract it from the found group distinguished name
                            if (GroupFoundDN.IsNotNullOrEmpty())
                            {
                                GroupFoundDomain = GroupFoundDN.Substring(GroupFoundDN.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                            }
                        }
                        Logger.Write_Verbose($@"[Get-DomainGroupMember] Using LDAP matching rule to recurse on '{GroupFoundDN}', only user accounts will be returned.");
                        GroupSearcher.Filter = $@"(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:={GroupFoundDN}))";
                        GroupSearcher.PropertiesToLoad.AddRange(new string[] { @"distinguishedName" });
                        var Results = GroupSearcher.FindAll();
                        if (Results != null)
                        {
                            Members = new List<string>();
                            foreach (SearchResult result in Results)
                            {
                                Members.Add(result.Properties[@"distinguishedname"][0] as string);
                            }
                        }
                    }
                }
                else
                {
                    var IdentityFilter = @"";
                    var Filter = @"";
                    if (args.Identity != null)
                    {
                        foreach (var item in args.Identity)
                        {
                            var IdentityInstance = item.Replace(@"(", @"\28").Replace(@")", @"\29");
                            if (new Regex(@"^S-1-").Match(IdentityInstance).Success)
                            {
                                IdentityFilter += $@"(objectsid={IdentityInstance})";
                            }
                            else if (new Regex(@"^CN=").Match(IdentityInstance).Success)
                            {
                                IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                                if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                                {
                                    // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                    //   and rebuild the domain searcher
                                    var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"".Replace(@",", @"."));
                                    Logger.Write_Verbose($@"[Get-DomainGroupMember] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                    SearcherArguments.Domain = IdentityDomain;
                                    GroupSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                    if (GroupSearcher == null)
                                    {
                                        Logger.Write_Warning($@"[Get-DomainGroupMember] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                    }
                                }
                            }
                            else if (new Regex(@"^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$").Match(IdentityInstance).Success)
                            {
                                var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                                IdentityFilter += $@"(objectguid={GuidByteString})";
                            }
                            else if (IdentityInstance.Contains(@"\"))
                            {
                                var ConvertedIdentityInstance = ConvertADName.Convert_ADName(new Args_Convert_ADName
                                {
                                    OutputType = ADSNameType.Canonical,
                                    Identity = new string[] { IdentityInstance.Replace(@"\28", @"(").Replace(@"\29", @")") }
                                });
                                if (ConvertedIdentityInstance != null && ConvertedIdentityInstance.Any())
                                {
                                    var GroupDomain = ConvertedIdentityInstance.First().Substring(0, ConvertedIdentityInstance.First().IndexOf('/'));
                                    var GroupName = IdentityInstance.Split(new char[] { '\\' })[1];
                                    IdentityFilter += $@"(samAccountName={GroupName})";
                                    SearcherArguments.Domain = GroupDomain;
                                    Logger.Write_Verbose($@"[Get-DomainGroupMember] Extracted domain '{GroupDomain}' from '{IdentityInstance}'");
                                    GroupSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                }
                            }
                            else
                            {
                                IdentityFilter += $@"(samAccountName={IdentityInstance})";
                            }
                        }
                    }

                    if (IdentityFilter != null && IdentityFilter.Trim() != @"")
                    {
                        Filter += $@"(|{IdentityFilter})";
                    }

                    if (args.LDAPFilter.IsNotNullOrEmpty())
                    {
                        Logger.Write_Verbose($@"[Get-DomainGroupMember] Using additional LDAP filter: {args.LDAPFilter}");
                        Filter += $@"{args.LDAPFilter}";
                    }

                    GroupSearcher.Filter = $@"(&(objectCategory=group){Filter})";
                    Logger.Write_Verbose($@"[Get-DomainGroupMember] Get-DomainGroupMember filter string: {GroupSearcher.Filter}");
                    SearchResult Result = null;
                    try
                    {
                        Result = GroupSearcher.FindOne();
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Get-DomainGroupMember] Error searching for group with identity '{args.Identity}': {e}");
                        Members = new List<string>();
                    }

                    GroupFoundName = @"";
                    GroupFoundDN = @"";

                    if (Result != null)
                    {
                        var tmpProperty = Result.Properties[@"member"];
                        var tmpValues = new string[tmpProperty.Count];
                        tmpProperty.CopyTo(tmpValues, 0);
                        Members = tmpValues.ToList();
                        string RangedProperty = "";

                        if (Members.Count == 0)
                        {
                            // ranged searching, thanks @meatballs__ !
                            var Finished = false;
                            var Bottom = 0;
                            var Top = 0;

                            while (!Finished)
                            {
                                Top = Bottom + 1499;
                                var MemberRange = $@"member;range={Bottom}-{Top}";
                                Bottom += 1500;
                                GroupSearcher.PropertiesToLoad.Clear();
                                GroupSearcher.PropertiesToLoad.Add($@"{MemberRange}");
                                GroupSearcher.PropertiesToLoad.Add(@"samaccountname");
                                GroupSearcher.PropertiesToLoad.Add(@"distinguishedname");

                                try
                                {
                                    Result = GroupSearcher.FindOne();
                                    RangedProperty = Result.Properties.PropertyNames.GetFirstMatch(@"member;range=*");
                                    tmpProperty = Result.Properties[RangedProperty];
                                    tmpValues = new string[tmpProperty.Count];
                                    tmpProperty.CopyTo(tmpValues, 0);
                                    Members.AddRange(tmpValues.ToList());
                                    GroupFoundName = Result.Properties[@"samaccountname"][0] as string;
                                    GroupFoundDN = Result.Properties[@"distinguishedname"][0] as string;

                                    if (Members.Count == 0)
                                    {
                                        Finished = true;
                                    }
                                }
                                catch
                                {
                                    Finished = true;
                                }
                            }
                        }
                        else
                        {
                            GroupFoundName = Result.Properties[@"samaccountname"][0] as string;
                            GroupFoundDN = Result.Properties[@"distinguishedname"][0] as string;
                            tmpProperty = Result.Properties[RangedProperty];
                            tmpValues = new string[tmpProperty.Count];
                            tmpProperty.CopyTo(tmpValues, 0);
                            Members.AddRange(tmpValues.ToList());
                        }

                        if (args.Domain.IsNotNullOrEmpty())
                        {
                            GroupFoundDomain = args.Domain;
                        }
                        else
                        {
                            // if a domain isn't passed, try to extract it from the found group distinguished name
                            if (GroupFoundDN.IsNotNullOrEmpty())
                            {
                                GroupFoundDomain = GroupFoundDN.Substring(GroupFoundDN.IndexOf(@"DC=")).Replace(@"DC=", @"".Replace(@",", @"."));
                            }
                        }
                    }

                    var UseMatchingRule = false;
                    string MemberDomain = null;
                    foreach (var Member in Members)
                    {
                        ResultPropertyCollection Properties = null;
                        if (args.Recurse && UseMatchingRule)
                        {
                            //$Properties = $_.Properties
                        }
                        else
                        {
                            var ObjectSearcherArguments = new Args_Get_DomainObject
                            {
                                ADSPath = SearcherArguments.ADSPath,
                                Credential = SearcherArguments.Credential,
                                Domain = SearcherArguments.Domain,
                                DomainController = SearcherArguments.DomainController,
                                Filter = SearcherArguments.Filter,
                                LDAPFilter = SearcherArguments.LDAPFilter,
                                Properties = SearcherArguments.Properties,
                                ResultPageSize = SearcherArguments.ResultPageSize,
                                SearchBase = SearcherArguments.SearchBase,
                                SearchScope = SearcherArguments.SearchScope,
                                SecurityMasks = SearcherArguments.SecurityMasks,
                                Server = SearcherArguments.Server,
                                ServerTimeLimit = SearcherArguments.ServerTimeLimit,
                                Tombstone = SearcherArguments.Tombstone
                            };
                            ObjectSearcherArguments.Identity = new string[] { Member };
                            ObjectSearcherArguments.Raw = true;
                            ObjectSearcherArguments.Properties = new string[] { @"distinguishedname", @"cn", @"samaccountname", @"objectsid", @"objectclass" };
                            var Object = GetDomainObject.Get_DomainObject(ObjectSearcherArguments)?.FirstOrDefault() as SearchResult;
                            Properties = Object.Properties;
                        }

                        if (Properties != null)
                        {
                            var GroupMember = new GroupMember
                            {
                                GroupDomain = GroupFoundDomain,
                                GroupName = GroupFoundName,
                                GroupDistinguishedName = GroupFoundDN
                            };

                            string MemberSID = null;
                            if (Properties["objectsid"] != null)
                            {
                                MemberSID = new System.Security.Principal.SecurityIdentifier(Properties["objectsid"][0] as byte[], 0).Value;
                            }
                            else
                            {
                                MemberSID = null;
                            }

                            string MemberDN = null;
                            try
                            {
                                MemberDN = Properties["distinguishedname"][0].ToString();
                                if (MemberDN.IsRegexMatch(@"ForeignSecurityPrincipals|S-1-5-21"))
                                {
                                    try
                                    {
                                        if (MemberSID.IsNullOrEmpty())
                                        {
                                            MemberSID = Properties["cn"][0].ToString();
                                        }
                                        ADNameArguments.Identity = new string[] { MemberSID };
                                        ADNameArguments.OutputType = ADSNameType.DomainSimple;
                                        var MemberSimpleName = ConvertADName.Convert_ADName(ADNameArguments);

                                        if (MemberSimpleName != null && MemberSimpleName.Any())
                                        {
                                            MemberDomain = MemberSimpleName.First().Split('@')[1];
                                        }
                                        else
                                        {
                                            Logger.Write_Warning($@"[Get-DomainGroupMember] Error converting {MemberDN}");
                                            MemberDomain = null;
                                        }
                                    }
                                    catch
                                    {
                                        Logger.Write_Warning($@"[Get-DomainGroupMember] Error converting {MemberDN}");
                                        MemberDomain = null;
                                    }
                                }
                                else
                                {
                                    // extract the FQDN from the Distinguished Name
                                    MemberDomain = MemberDN.Substring(MemberDN.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                }
                            }
                            catch
                            {
                                MemberDN = null;
                                MemberDomain = null;
                            }
                            string MemberName = null;
                            if (Properties["samaccountname"] != null)
                            {
                                // forest users have the samAccountName set
                                MemberName = Properties["samaccountname"][0].ToString();
                            }
                            else
                            {
                                // external trust users have a SID, so convert it
                                try
                                {
                                    MemberName = ConvertFromSID.ConvertFrom_SID(new Args_ConvertFrom_SID
                                    {
                                        ObjectSID = new string[] { Properties["cn"][0].ToString() },
                                        Domain = ADNameArguments.Domain,
                                        Server = ADNameArguments.Server,
                                        Credential = ADNameArguments.Credential
                                    }).First();
                                }
                                catch
                                {
                                    // if there's a problem contacting the domain to resolve the SID
                                    MemberName = Properties["cn"][0].ToString();
                                }
                            }

                            string MemberObjectClass = null;
                            if (Properties["objectclass"].RegexContains(@"computer"))
                            {
                                MemberObjectClass = @"computer";
                            }
                            else if (Properties["objectclass"].RegexContains(@"group"))
                            {
                                MemberObjectClass = @"group";
                            }
                            else if (Properties["objectclass"].RegexContains(@"user"))
                            {
                                MemberObjectClass = @"user";
                            }
                            else
                            {
                                MemberObjectClass = null;
                            }
                            GroupMember.MemberDomain = MemberDomain;
                            GroupMember.MemberName = MemberName;
                            GroupMember.MemberDistinguishedName = MemberDN;
                            GroupMember.MemberObjectClass = MemberObjectClass;
                            GroupMember.MemberSID = MemberSID;
                            GroupMembers.Add(GroupMember);

                            // if we're doing manual recursion
                            if (args.Recurse && MemberDN.IsNotNullOrEmpty() && MemberObjectClass.IsRegexMatch(@"group"))
                            {
                                Logger.Write_Verbose($@"[Get-DomainGroupMember] Manually recursing on group: {MemberDN}");
                                var GroupArguments = new Args_Get_DomainGroupMember()
                                {
                                    Domain = SearcherArguments.Domain,
                                    LDAPFilter = SearcherArguments.LDAPFilter,
                                    SearchBase = SearcherArguments.SearchBase,
                                    Server = SearcherArguments.Server,
                                    SearchScope = SearcherArguments.SearchScope,
                                    ResultPageSize = SearcherArguments.ResultPageSize,
                                    ServerTimeLimit = SearcherArguments.ServerTimeLimit,
                                    Tombstone = SearcherArguments.Tombstone,
                                    Credential = SearcherArguments.Credential,
                                    Identity = new string[] { MemberDN }
                                };
                                GroupMembers.AddRange(Get_DomainGroupMember(GroupArguments));
                            }
                        }
                    }
                }
                GroupSearcher.Dispose();
            }
            return GroupMembers;
        }

    }
}
