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
    class GetDomainComputer
    { 
        public static IEnumerable<object> Get_DomainComputer(Args_Get_DomainComputer args = null)
        {
            if (args == null) args = new Args_Get_DomainComputer();

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

            var CompSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
            var Computers = new List<object>();

            if (CompSearcher != null)
            {
                var IdentityFilter = @"";
                var Filter = @"";
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
                                Logger.Write_Verbose($@"[Get-DomainComputer] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                CompSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                if (CompSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainComputer] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
                        }
                        else if (IdentityInstance.Contains(@"."))
                        {
                            IdentityFilter += $@"(|(name={IdentityInstance})(dnshostname={IdentityInstance}))";
                        }
                        else if (new Regex(@"^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$").Match(IdentityInstance).Success)
                        {
                            var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                            IdentityFilter += $@"(objectguid={GuidByteString})";
                        }
                        else
                        {
                            IdentityFilter += $@"(name={IdentityInstance})";
                        }
                    }
                }
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += $@"(|{IdentityFilter})";
                }

                if (args.Unconstrained)
                {
                    Logger.Write_Verbose(@"[Get-DomainComputer] Searching for computers with for unconstrained delegation");
                    Filter += @"(userAccountControl:1.2.840.113556.1.4.803:=524288)";
                }
                if (args.TrustedToAuth)
                {
                    Logger.Write_Verbose(@"[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals");
                    Filter += @"(msds-allowedtodelegateto=*)";
                }
                if (args.Printers)
                {
                    Logger.Write_Verbose("[Get-DomainComputer] Searching for printers");
                    Filter += @"(objectCategory=printQueue)";
                }
                if (args.SPN.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Searching for computers with SPN: {args.SPN}");
                    Filter += $@"(servicePrincipalName={args.SPN})";
                }
                if (args.OperatingSystem.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Searching for computers with operating system: {args.OperatingSystem}");
                    Filter += $@"(operatingsystem={args.OperatingSystem})";
                }
                if (args.ServicePack.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Searching for computers with service pack: {args.ServicePack}");
                    Filter += $@"(operatingsystemservicepack={args.ServicePack})";
                }
                if (args.SiteName.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Searching for computers with site name: {args.SiteName}");
                    Filter += $@"(serverreferencebl={args.SiteName})";
                }
                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Using additional LDAP filter: {args.LDAPFilter}");
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

                CompSearcher.Filter = $@"(&(samAccountType=805306369){Filter})";
                Logger.Write_Verbose($@"[Get-DomainComputer] Get-DomainComputer filter string: {CompSearcher.Filter}");

                if (args.FindOne)
                {
                    var result = CompSearcher.FindOne();
                    var Up = true;
                    if (args.Ping)
                    {
                        Up = TestConnection.Ping(result.Properties["dnshostname"][0] as string, 1);
                    }
                    if (Up)
                    {
                        if (args.Raw)
                        {
                            // return raw result objects
                            Computers.Add(result);
                        }
                        else
                        {
                            Computers.Add(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                        }
                    }
                }
                else
                {
                    var Results = CompSearcher.FindAll();
                    foreach (SearchResult result in Results)
                    {
                        var Up = true;
                        if (args.Ping)
                        {
                            Up = TestConnection.Ping(result.Properties["dnshostname"][0] as string, 1);
                        }
                        if (Up)
                        {
                            if (args.Raw)
                            {
                                // return raw result objects
                                Computers.Add(result);
                            }
                            else
                            {
                                Computers.Add(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                            }
                        }
                    }
                    if (Results != null)
                    {
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainComputer] Error disposing of the Results object: {e}");
                        }
                    }
                }
                CompSearcher.Dispose();
            }
            return Computers;
        }

    }
}
