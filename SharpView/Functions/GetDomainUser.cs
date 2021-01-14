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
    class GetDomainUser
    { 
        public static IEnumerable<object> Get_DomainUser(Args_Get_DomainUser args = null)
        {
            if (args == null) args = new Args_Get_DomainUser();

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

            var UserSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
            var Users = new List<object>();

            if (UserSearcher != null)
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
                                Logger.Write_Verbose($@"[Get-DomainUser] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                UserSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                if (UserSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainUser] Unable to retrieve domain searcher for '{IdentityDomain}'");
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
                                var UserDomain = ConvertedIdentityInstance.First().Substring(0, ConvertedIdentityInstance.First().IndexOf('/'));
                                var UserName = IdentityInstance.Split(new char[] { '\\' })[1];
                                IdentityFilter += $@"(samAccountName={UserName})";
                                SearcherArguments.Domain = UserDomain;
                                Logger.Write_Verbose($@"[Get-DomainUser] Extracted domain '{UserDomain}' from '{IdentityInstance}'");
                                UserSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                            }
                        }
                        else
                        {
                            IdentityFilter += $@"(samAccountName={IdentityInstance})";
                        }
                    }
                }

                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += $@"(|{IdentityFilter})";
                }

                if (args.SPN)
                {
                    Logger.Write_Verbose(@"[Get-DomainUser] Searching for non-null service principal names");
                    Filter += "(servicePrincipalName=*)";
                }
                if (args.AllowDelegation)
                {
                    Logger.Write_Verbose(@"[Get-DomainUser] Searching for users who can be delegated");
                    // negation of "Accounts that are sensitive and not trusted for delegation"
                    Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))";
                }
                if (args.DisallowDelegation)
                {
                    Logger.Write_Verbose(@"[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation");
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=1048574)";
                }
                if (args.AdminCount)
                {
                    Logger.Write_Verbose(@"[Get-DomainUser] Searching for adminCount=1");
                    Filter += "(admincount=1)";
                }
                if (args.TrustedToAuth)
                {
                    Logger.Write_Verbose("[Get-DomainUser] Searching for users that are trusted to authenticate for other principals");
                    Filter += "(msds-allowedtodelegateto=*)";
                }
                if (args.PreauthNotRequired)
                {
                    Logger.Write_Verbose("[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate");
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
                }
                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainUser] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }

                // build the LDAP filter for the dynamic UAC filter value
                var uacs = args.UACFilter.ExtractValues();
                foreach (var uac in uacs)
                {
                    if (uac.IsNot())
                    {
                        Filter += $@"(!(userAccountControl:1.2.840.113556.1.4.803:={uac.GetValueAsInteger()}))";
                    }
                    else
                    {
                        Filter += $@"(userAccountControl:1.2.840.113556.1.4.803:={uac.GetValueAsInteger()})";
                    }
                }

                UserSearcher.Filter = $@"(&(samAccountType=805306368){Filter})";
                Logger.Write_Verbose($@"[Get-DomainUser] filter string: {UserSearcher.Filter}");

                if (args.FindOne)
                {
                    var result = UserSearcher.FindOne();
                    if (args.Raw)
                    {
                        // return raw result objects
                        Users.Add(result);
                    }
                    else
                    {
                        Users.Add(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                    }
                }
                else
                {
                    var Results = UserSearcher.FindAll();
                    foreach (SearchResult result in Results)
                    {
                        if (args.Raw)
                        {
                            // return raw result objects
                            Users.Add(result);
                        }
                        else
                        {
                            Users.Add(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                        }
                    }
                    if (Results != null)
                    {
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainUser] Error disposing of the Results object: {e}");
                        }
                    }
                }
                UserSearcher.Dispose();
            }
            return Users;
        }

    }
}
