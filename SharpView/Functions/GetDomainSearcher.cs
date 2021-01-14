using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.Xml;
using System.Runtime.InteropServices;
using System.DirectoryServices.ActiveDirectory;
using SharpView.Arguments;
using SharpView.Returns;
using SharpView.Enums;
using SharpView.Utils;

namespace SharpView.Functions
{
    class GetDomainSearcher
    {
        /* connect ldap server & create an searcher object */
        public static System.DirectoryServices.DirectorySearcher Get_DomainSearcher(Args_Get_DomainSearcher args = null)
        {
            if (args == null) args = new Args_Get_DomainSearcher();

            string TargetDomain = null;
            string BindServer = null;

            var userDnsDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");

            if (args.Domain.IsNotNullOrEmpty())
            {
                TargetDomain = args.Domain;

                if (userDnsDomain != null && userDnsDomain.Trim() != "")
                {
                    // see if we can grab the user DNS logon domain from environment variables
                    var UserDomain = userDnsDomain;
                    var logonServer = Environment.GetEnvironmentVariable("LOGONSERVER");
                    if (logonServer != null && logonServer.Trim() != "" && UserDomain.IsNotNullOrEmpty())
                    {
                        BindServer = $"{logonServer.Replace(@"\\", "")}.{UserDomain}";
                    }
                }
            }
            else if (args.Credential != null)
            {
                // if not -Domain is specified, but -Credential is, try to retrieve the current domain name with Get-Domain
                var DomainObject = GetDomain.Get_Domain(new Args_Get_Domain { Credential = args.Credential });
                BindServer = DomainObject.PdcRoleOwner.Name;
                TargetDomain = DomainObject.Name;
            }
            else if (userDnsDomain != null && userDnsDomain.Trim() != "")
            {
                // see if we can grab the user DNS logon domain from environment variables
                TargetDomain = userDnsDomain;
                var logonServer = Environment.GetEnvironmentVariable("LOGONSERVER");
                if (logonServer != null && logonServer.Trim() != "" && TargetDomain.IsNotNullOrEmpty())
                {
                    BindServer = $"{logonServer.Replace(@"\\", "")}.{TargetDomain}";
                }
            }
            else
            {
                // otherwise, resort to Get-Domain to retrieve the current domain object
                var DomainObject = GetDomain.Get_Domain();
                if (DomainObject == null)
                {
                    System.Environment.Exit(0);
                }
                BindServer = DomainObject.PdcRoleOwner.Name;
                TargetDomain = DomainObject.Name;
            }

            if (args.Server.IsNotNullOrEmpty())
            {
                // if there's not a specified server to bind to, try to pull a logon server from ENV variables
                BindServer = args.Server;
            }

            var SearchString = "LDAP://";

            if (BindServer != null && BindServer.Trim() != "")
            {
                SearchString += BindServer;
                if (TargetDomain.IsNotNullOrEmpty())
                {
                    SearchString += '/';
                }
            }

            if (args.SearchBasePrefix.IsNotNullOrEmpty())
            {
                SearchString += args.SearchBasePrefix + @",";
            }

            var DN = string.Empty;
            if (args.SearchBase.IsNotNullOrEmpty())
            {
                if (new Regex(@"^GC://").Match(args.SearchBase).Success)
                {
                    // if we're searching the global catalog, get the path in the right format
                    DN = args.SearchBase.ToUpper().Trim('/');
                    SearchString = string.Empty;
                }
                else
                {
                    if (new Regex(@"^LDAP://").Match(args.SearchBase).Success)
                    {
                        if (new Regex(@"LDAP://.+/.+").Match(args.SearchBase).Success)
                        {
                            SearchString = string.Empty;
                            DN = args.SearchBase;
                        }
                        else
                        {
                            DN = args.SearchBase.Substring(7);
                        }
                    }
                    else
                    {
                        DN = args.SearchBase;
                    }
                }
            }
            else
            {
                // transform the target domain name into a distinguishedName if an ADS search base is not specified
                if (TargetDomain != null && TargetDomain.Trim() != "")
                {
                    DN = $"DC={TargetDomain.Replace(".", ",DC=")}";
                }
            }

            SearchString += DN;
            Logger.Write_Verbose($@"[Get-DomainSearcher] search base: {SearchString}");

            System.DirectoryServices.DirectorySearcher Searcher = null;
            if (args.Credential != null)
            {
                Logger.Write_Verbose(@"[Get-DomainSearcher] Using alternate credentials for LDAP connection");
                // bind to the inital search object using alternate credentials
                var DomainObject = new System.DirectoryServices.DirectoryEntry(SearchString, args.Credential.UserName, args.Credential.Password);
                Searcher = new System.DirectoryServices.DirectorySearcher(DomainObject);
            }
            else
            {
                // bind to the inital object using the current credentials
                //Searcher = new System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
                var DomainObject = new System.DirectoryServices.DirectoryEntry(SearchString);
                Searcher = new System.DirectoryServices.DirectorySearcher(DomainObject);
            }

            Searcher.PageSize = args.ResultPageSize;
            Searcher.SearchScope = args.SearchScope;
            Searcher.CacheResults = false;
            Searcher.ReferralChasing = System.DirectoryServices.ReferralChasingOption.All;

            if (args.ServerTimeLimit != null)
            {
                Searcher.ServerTimeLimit = new TimeSpan(0, 0, args.ServerTimeLimit.Value);
            }

            if (args.Tombstone)
            {
                Searcher.Tombstone = true;
            }

            if (args.LDAPFilter.IsNotNullOrWhiteSpace())
            {
                Searcher.Filter = args.LDAPFilter;
            }

            if (args.SecurityMasks != null)
            {
                Searcher.SecurityMasks = args.SecurityMasks.Value;
            }

            if (args.Properties != null)
            {
                // handle an array of properties to load w/ the possibility of comma-separated strings
                var PropertiesToLoad = new List<string>();
                foreach (var item in args.Properties)
                {
                    PropertiesToLoad.AddRange(item.Split(','));
                }

                Searcher.PropertiesToLoad.AddRange(PropertiesToLoad.ToArray());
            }

            return Searcher;
        }
    }
}
