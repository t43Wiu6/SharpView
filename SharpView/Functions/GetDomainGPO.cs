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
    class GetDomainGPO
    { 
        public static IEnumerable<object> Get_DomainGPO(Args_Get_DomainGPO args = null)
        {
            if (args == null) args = new Args_Get_DomainGPO();

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
            var GPOSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);

            var GPOs = new List<object>();
            if (GPOSearcher != null)
            {
                if (args.ComputerIdentity != null || args.UserIdentity != null)
                {
                    var GPOAdsPaths = new List<string>();
                    string[] OldProperties = null;
                    if (SearcherArguments.Properties != null)
                    {
                        OldProperties = SearcherArguments.Properties;
                    }
                    SearcherArguments.Properties = new[] { @"distinguishedname", @"dnshostname" };
                    string TargetComputerName = null;
                    string ObjectDN = null;

                    if (args.ComputerIdentity.IsNotNullOrEmpty())
                    {
                        var Computer = GetDomainComputer.Get_DomainComputer(new Args_Get_DomainComputer(SearcherArguments)
                        {
                            Identity = new[] { args.ComputerIdentity },
                            FindOne = true
                        }).First() as LDAPProperty;
                        if (Computer == null)
                        {
                            Logger.Write_Verbose($@"[Get-DomainGPO] Computer '{args.ComputerIdentity}' not found!");
                        }
                        ObjectDN = Computer.distinguishedname;
                        TargetComputerName = Computer.dnshostname;
                    }
                    else
                    {
                        var User = GetDomainUser.Get_DomainUser(new Args_Get_DomainUser(SearcherArguments)
                        {
                            Identity = new[] { args.UserIdentity },
                            FindOne = true
                        }) as LDAPProperty;
                        if (User == null)
                        {
                            Logger.Write_Verbose($@"[Get-DomainGPO] User '{args.UserIdentity}' not found!");
                        }
                        ObjectDN = User.distinguishedname;
                    }

                    // extract all OUs the target user/computer is a part of
                    var ObjectOUs = new List<string>();
                    foreach (var item in ObjectDN.Split(','))
                    {
                        if (item.StartsWith(@"OU="))
                        {
                            ObjectOUs.Add(ObjectDN.Substring(ObjectDN.IndexOf($@"{item},")));
                        }
                    }
                    Logger.Write_Verbose($@"[Get-DomainGPO] object OUs: {ObjectOUs}");

                    if (ObjectOUs != null)
                    {
                        // find all the GPOs linked to the user/computer's OUs
                        SearcherArguments.Properties = null;
                        var InheritanceDisabled = false;
                        foreach (var ObjectOU in ObjectOUs)
                        {
                            var ous = GetDomainOU.Get_DomainOU(new Args_Get_DomainOU(SearcherArguments)
                            {
                                Identity = new[] { ObjectOU }
                            });
                            foreach (LDAPProperty ou in ous)
                            {
                                // extract any GPO links for this particular OU the computer is a part of
                                if (ou.gplink.IsNotNullOrEmpty())
                                {
                                    foreach (var item in ou.gplink.Split(new[] { @"][" }, StringSplitOptions.None))
                                    {
                                        if (item.StartsWith(@"LDAP"))
                                        {
                                            var Parts = item.Split(';');
                                            var GpoDN = Parts[0];
                                            var Enforced = Parts[1];

                                            if (InheritanceDisabled)
                                            {
                                                // if inheritance has already been disabled and this GPO is set as "enforced"
                                                // then add it, otherwise ignore it
                                                if (Enforced == @"2")
                                                {
                                                    GPOAdsPaths.Add(GpoDN);
                                                }
                                            }
                                            else
                                            {
                                                // inheritance not marked as disabled yet
                                                GPOAdsPaths.Add(GpoDN);
                                            }
                                        }
                                    }
                                }

                                //if this OU has GPO inheritence disabled, break so additional OUs aren't processed
                                if (ou.gpoptions == 1)
                                {
                                    InheritanceDisabled = true;
                                }
                            }
                        }
                    }

                    if (TargetComputerName.IsNotNullOrEmpty())
                    {
                        // find all the GPOs linked to the computer's site
                        var ComputerSite = GetNetComputerSiteName.Get_NetComputerSiteName(new Args_Get_NetComputerSiteName { ComputerName = new[] { TargetComputerName } }).First().SiteName;
                        if (ComputerSite.IsNotNullOrEmpty() && !ComputerSite.IsLikeMatch(@"Error*"))
                        {
                            var sites = GetDomainSite.Get_DomainSite(new Args_Get_DomainSite(SearcherArguments)
                            {
                                Identity = new[] { ComputerSite }
                            });
                            foreach (LDAPProperty site in sites)
                            {
                                if (site.gplink.IsNotNullOrEmpty())
                                {
                                    // extract any GPO links for this particular site the computer is a part of
                                    foreach (var item in site.gplink.Split(new[] { @"][" }, StringSplitOptions.None))
                                    {
                                        if (item.StartsWith(@"LDAP"))
                                        {
                                            GPOAdsPaths.Add(item.Split(';')[0]);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // find any GPOs linked to the user/computer's domain
                    var ObjectDomainDN = ObjectDN.Substring(ObjectDN.IndexOf(@"DC="));
                    SearcherArguments.Properties = null;
                    SearcherArguments.LDAPFilter = $@"(objectclass=domain)(distinguishedname={ObjectDomainDN})";
                    var objs = GetDomainObject.Get_DomainObject(new Args_Get_DomainObject(SearcherArguments));
                    foreach (LDAPProperty obj in objs)
                    {
                        if (obj.gplink.IsNotNullOrEmpty())
                        {
                            // extract any GPO links for this particular domain the computer is a part of
                            foreach (var item in obj.gplink.Split(new[] { @"][" }, StringSplitOptions.None))
                            {
                                if (item.StartsWith(@"LDAP"))
                                {
                                    GPOAdsPaths.Add(item.Split(';')[0]);
                                }
                            }
                        }
                    }
                    Logger.Write_Verbose($@"[Get-DomainGPO] GPOAdsPaths: {GPOAdsPaths}");

                    // restore the old properites to return, if set
                    if (OldProperties != null) { SearcherArguments.Properties = OldProperties; }
                    else { SearcherArguments.Properties = null; }

                    foreach (var path in GPOAdsPaths.Where(x => x != null && x != ""))
                    {
                        // use the gplink as an ADS path to enumerate all GPOs for the computer
                        SearcherArguments.SearchBase = path;
                        SearcherArguments.LDAPFilter = @"(objectCategory=groupPolicyContainer)";
                        objs = GetDomainObject.Get_DomainObject(new Args_Get_DomainObject(SearcherArguments));
                        foreach (LDAPProperty obj in objs)
                        {
                            GPOs.Add(new GPO(obj));
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
                            if (IdentityInstance.IsRegexMatch(@"LDAP://|^CN=.*"))
                            {
                                IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                                if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                                {
                                    // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                    // and rebuild the domain searcher
                                    var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                    Logger.Write_Verbose($@"[Get-DomainGPO] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                    SearcherArguments.Domain = IdentityDomain;
                                    GPOSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                    if (GPOSearcher == null)
                                    {
                                        Logger.Write_Warning($@"[Get-DomainGPO] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                    }
                                }
                            }
                            else if (IdentityInstance.IsRegexMatch(@"{.*}"))
                            {
                                IdentityFilter += $@"(name={IdentityInstance})";
                            }
                            else
                            {
                                try
                                {
                                    var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                                    IdentityFilter += $@"(objectguid={GuidByteString})";
                                }
                                catch
                                {
                                    IdentityFilter += $@"(displayname={IdentityInstance})";
                                }
                            }
                        }
                    }

                    if (IdentityFilter != null && IdentityFilter.Trim() != @"")
                    {
                        Filter += $@"(|{IdentityFilter})";
                    }

                    if (args.LDAPFilter.IsNotNullOrEmpty())
                    {
                        Logger.Write_Verbose($@"[Get-DomainGPO] Using additional LDAP filter: {args.LDAPFilter}");
                        Filter += $@"{args.LDAPFilter}";
                    }

                    GPOSearcher.Filter = $@"(&(objectCategory=groupPolicyContainer){Filter})";
                    Logger.Write_Verbose($@"[Get-DomainGPO] filter string: {GPOSearcher.Filter}");

                    SearchResult[] Results = null;
                    if (args.FindOne) { Results = new SearchResult[] { GPOSearcher.FindOne() }; }
                    else
                    {
                        var items = GPOSearcher.FindAll();
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
                            if (args.Raw)
                            {
                                // return raw result objects
                                GPOs.Add(result);
                            }
                            else
                            {
                                GPO GPO;
                                if (args.SearchBase.IsNotNullOrEmpty() && args.SearchBase.IsRegexMatch(@"^GC://"))
                                {
                                    GPO = new GPO(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                                    try
                                    {
                                        var GPODN = GPO.distinguishedname;
                                        var GPODomain = GPODN.Substring(GPODN.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                        var gpcfilesyspath = $@"\\{GPODomain}\SysVol\{GPODomain}\Policies\{GPO.cn}";
                                        GPO.gpcfilesyspath = gpcfilesyspath;
                                    }
                                    catch
                                    {
                                        Logger.Write_Verbose($@"[Get-DomainGPO] Error calculating gpcfilesyspath for: {GPO.distinguishedname}");
                                    }
                                }
                                else
                                {
                                    GPO = new GPO(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                                }
                                GPOs.Add(GPO);
                            }
                        }
                    }
                }
                GPOSearcher.Dispose();
            }
            return GPOs;
        }

    }
}
