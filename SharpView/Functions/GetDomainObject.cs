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
    class GetDomainObject
    { 
        public static IEnumerable<object> Get_DomainObject(Args_Get_DomainObject args = null)
        {
            if (args == null) args = new Args_Get_DomainObject();

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

            var ObjectSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
            var Objects = new List<object>();

            if (ObjectSearcher != null)
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
                        else if (new Regex(@"^(CN|OU|DC)=").Match(IdentityInstance).Success)
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                // and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                Logger.Write_Verbose($@"[Get-DomainObject] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                ObjectSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                if (ObjectSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainObject] Unable to retrieve domain searcher for '{IdentityDomain}'");
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
                                var ObjectDomain = ConvertedIdentityInstance.First().Substring(0, ConvertedIdentityInstance.First().IndexOf('/'));
                                var ObjectName = IdentityInstance.Split(new char[] { '\\' })[1];
                                IdentityFilter += $@"(samAccountName={ObjectName})";
                                SearcherArguments.Domain = ObjectDomain;
                                Logger.Write_Verbose($@"[Get-DomainObject] Extracted domain '{ObjectDomain}' from '{IdentityInstance}'");
                                ObjectSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                            }
                        }
                        else if (IdentityInstance.Contains(@"."))
                        {
                            IdentityFilter += $@"(|(samAccountName={IdentityInstance})(name={IdentityInstance})(dnshostname={IdentityInstance}))";
                        }
                        else
                        {
                            IdentityFilter += $@"(|(samAccountName={IdentityInstance})(name={IdentityInstance})(displayname={IdentityInstance}))";
                        }
                    }
                }
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += $@"(|{IdentityFilter})";
                }
                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainObject] Using additional LDAP filter: {args.LDAPFilter}");
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
                if (Filter != null && Filter != "")
                {
                    ObjectSearcher.Filter = $@"(&{Filter})";
                }
                Logger.Write_Verbose($@"[Get-DomainObject] Get-DomainComputer filter string: {ObjectSearcher.Filter}");

                if (args.FindOne)
                {
                    var result = ObjectSearcher.FindOne();
                    if (args.Raw)
                    {
                        // return raw result objects
                        Objects.Add(result);
                    }
                    else
                    {
                        Objects.Add(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                    }
                }
                else
                {
                    var Results = ObjectSearcher.FindAll();
                    foreach (SearchResult result in Results)
                    {
                        if (args.Raw)
                        {
                            // return raw result objects
                            Objects.Add(result);
                        }
                        else
                        {
                            Objects.Add(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                        }
                    }
                    if (Results != null)
                    {
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainObject] Error disposing of the Results object: {e}");
                        }
                    }
                }
                ObjectSearcher.Dispose();
            }
            return Objects;
        }

    }
}
