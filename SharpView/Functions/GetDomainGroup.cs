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
    class GetDomainGroup
    { 
        public static IEnumerable<object> Get_DomainGroup(Args_Get_DomainGroup args = null)
        {
            if (args == null) args = new Args_Get_DomainGroup();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ObjectArguments = new Args_Get_DomainObject
            {
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var GroupSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
            var Groups = new List<object>();

            if (GroupSearcher != null)
            {
                if (args.MemberIdentity != null)
                {
                    string[] OldProperties = null;
                    if (args.Properties != null)
                    {
                        OldProperties = SearcherArguments.Properties;
                    }

                    ObjectArguments.Identity = args.MemberIdentity;
                    ObjectArguments.Raw = true;

                    var Objects = GetDomainObject.Get_DomainObject(ObjectArguments);
                    if (Objects != null)
                    {

                    }
                    foreach (SearchResult obj in Objects)
                    {
                        // convert the user/group to a directory entry
                        var ObjectDirectoryEntry = obj.GetDirectoryEntry();

                        // cause the cache to calculate the token groups for the user/group
                        ObjectDirectoryEntry.RefreshCache(new string[] { @"tokenGroups" });
                        foreach (byte[] tokenGroup in ObjectDirectoryEntry.Properties[@"tokenGroups"])
                        {
                            // convert the token group sid
                            var GroupSid = new System.Security.Principal.SecurityIdentifier(tokenGroup, 0).Value;

                            // ignore the built in groups
                            if (new Regex(@"^S-1-5-32-.*").Match(GroupSid).Success == false)
                            {
                                ObjectArguments.Identity = new string[] { GroupSid };
                                ObjectArguments.Raw = false;
                                if (OldProperties != null) { ObjectArguments.Properties = OldProperties; }
                                var Group = GetDomainObject.Get_DomainObject(ObjectArguments);
                                if (Group != null)
                                {
                                    Groups.AddRange(Group);
                                }
                            }
                        }
                    }
                }
                else
                {
                    var IdentityFilter = "";
                    var Filter = "";
                    if (args.Identity != null)
                    {
                        foreach (var samName in args.Identity)
                        {
                            var IdentityInstance = samName.Replace(@"(", @"\28").Replace(@")", @"\29");
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
                                    // and rebuild the domain searcher
                                    var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                    Logger.Write_Verbose($@"[Get-DomainGroup] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                    SearcherArguments.Domain = IdentityDomain;
                                    GroupSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                    if (GroupSearcher == null)
                                    {
                                        Logger.Write_Warning($@"[Get-DomainGroup] Unable to retrieve domain searcher for '{IdentityDomain}'");
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
                                    Logger.Write_Verbose($@"[Get-DomainUser] Extracted domain '{GroupDomain}' from '{IdentityInstance}'");
                                    GroupSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                }
                            }
                            else
                            {
                                IdentityFilter += $@"(|(samAccountName={IdentityInstance})(name={IdentityInstance}))";
                            }
                        }
                    }

                    if (IdentityFilter != null && IdentityFilter.Trim() != "")
                    {
                        Filter += $@"(|{IdentityFilter})";
                    }

                    if (args.AdminCount)
                    {
                        Logger.Write_Verbose(@"[Get-DomainGroup] Searching for adminCount=1");
                        Filter += "(admincount=1)";
                    }
                    if (args.GroupScope != null)
                    {
                        switch (args.GroupScope.Value)
                        {
                            case GroupScope.DomainLocal:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=4)";
                                break;
                            case GroupScope.NotDomainLocal:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=4))";
                                break;
                            case GroupScope.Global:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=2)";
                                break;
                            case GroupScope.NotGlobal:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=2))";
                                break;
                            case GroupScope.Universal:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=8)";
                                break;
                            case GroupScope.NotUniversal:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=8))";
                                break;
                            default:
                                break;
                        }
                        Logger.Write_Verbose($@"[Get-DomainGroup] Searching for group scope '{args.GroupScope.Value.ToString()}'");
                    }
                    if (args.GroupProperty != null)
                    {
                        switch (args.GroupProperty.Value)
                        {
                            case GroupProperty.Security:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=2147483648)";
                                break;
                            case GroupProperty.Distribution:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=2147483648))";
                                break;
                            case GroupProperty.CreatedBySystem:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=1)";
                                break;
                            case GroupProperty.NotCreatedBySystem:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=1))";
                                break;
                            default:
                                break;
                        }
                        Logger.Write_Verbose($@"[Get-DomainGroup] Searching for group property '{args.GroupProperty.Value.ToString()}'");
                    }
                    if (args.LDAPFilter.IsNotNullOrEmpty())
                    {
                        Logger.Write_Verbose($@"[Get-DomainGroup] Using additional LDAP filter: {args.LDAPFilter}");
                        Filter += $@"{args.LDAPFilter}";
                    }

                    GroupSearcher.Filter = $@"(&(objectCategory=group){Filter})";
                    Logger.Write_Verbose($@"[Get-DomainGroup] filter string: {GroupSearcher.Filter}");

                    if (args.FindOne)
                    {
                        var result = GroupSearcher.FindOne();
                        if (args.Raw)
                        {
                            // return raw result objects
                            Groups.Add(result);
                        }
                        else
                        {
                            Groups.Add(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                        }
                    }
                    else
                    {
                        var Results = GroupSearcher.FindAll();
                        foreach (SearchResult result in Results)
                        {
                            if (args.Raw)
                            {
                                // return raw result objects
                                Groups.Add(result);
                            }
                            else
                            {
                                Groups.Add(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                            }
                        }
                        if (Results != null)
                        {
                            try { Results.Dispose(); }
                            catch (Exception e)
                            {
                                Logger.Write_Verbose($@"[Get-DomainGroup] Error disposing of the Results object: {e}");
                            }
                        }
                    }
                    GroupSearcher.Dispose();
                }
            }
            return Groups;
        }

    }
}
