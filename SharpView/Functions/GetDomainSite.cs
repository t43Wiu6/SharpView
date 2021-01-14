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
    class GetDomainSite
    { 
        public static IEnumerable<object> Get_DomainSite(Args_Get_DomainSite args = null)
        {
            if (args == null) args = new Args_Get_DomainSite();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                SearchBasePrefix = @"CN=Sites,CN=Configuration",
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
            var SiteSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
            var Sites = new List<object>();
            if (SiteSearcher != null)
            {
                var IdentityFilter = @"";
                var Filter = @"";
                if (args.Identity != null)
                {
                    foreach (var item in args.Identity)
                    {
                        var IdentityInstance = item.Replace(@"(", @"\28").Replace(@")", @"\29");
                        if (IdentityInstance.IsRegexMatch(@"^CN=.*"))
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                //   and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                Logger.Write_Verbose($@"[Get-DomainSite] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                SiteSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                if (SiteSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainSite] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
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
                                IdentityFilter += $@"(name={IdentityInstance})";
                            }
                        }
                    }
                }
                if (IdentityFilter != null && IdentityFilter.Trim() != @"")
                {
                    Filter += $@"(|{IdentityFilter})";
                }

                if (args.GPLink.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainSite] Searching for sites with {args.GPLink} set in the gpLink property");
                    Filter += $@"(gplink=*{args.GPLink}*)";
                }

                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainSite] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }

                SiteSearcher.Filter = $@"(&(objectCategory=site){Filter})";
                Logger.Write_Verbose($@"[Get-DomainSite] Get-DomainSite filter string: {SiteSearcher.Filter}");

                SearchResult[] Results = null;
                if (args.FindOne) { Results = new SearchResult[] { SiteSearcher.FindOne() }; }
                else
                {
                    var items = SiteSearcher.FindAll();
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
                            Sites.Add(result);
                        }
                        else
                        {
                            var Site = ConvertLDAPProperty.Convert_LDAPProperty(result.Properties);
                            Sites.Add(Site);
                        }
                    }
                }
                SiteSearcher.Dispose();
            }
            return Sites;
        }

    }
}
