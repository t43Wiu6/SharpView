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
    class GetDomainObjectAcl
    { 
        public static IEnumerable<ACL> Get_DomainObjectAcl(Args_Get_DomainObjectAcl args = null)
        {
            if (args == null) args = new Args_Get_DomainObjectAcl();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                Properties = new[] { "samaccountname", "ntsecuritydescriptor", "distinguishedname", "objectsid" },
                SecurityMasks = args.Sacl ? SecurityMasks.Sacl : SecurityMasks.Dacl,
                Domain = args.Domain,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var Searcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);

            var DomainGUIDMapArguments = new Args_Get_DomainGUIDMap
            {
                Domain = args.Domain,
                Server = args.Server,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Credential = args.Credential
            };

            // get a GUID -> name mapping
            IDictionary<string, string> GUIDs = null;
            if (args.ResolveGUIDs)
            {
                GUIDs = GetDomainGUIDMap.Get_DomainGUIDMap(DomainGUIDMapArguments);
            }

            var ACLs = new List<ACL>();
            if (Searcher != null)
            {
                var IdentityFilter = "";
                var Filter = "";
                if (args.Identity != null)
                {
                    foreach (var item in args.Identity)
                    {
                        var IdentityInstance = item.Replace(@"(", @"\28").Replace(@")", @"\29");
                        if (IdentityInstance.IsRegexMatch(@"^S-1-.*"))
                        {
                            IdentityFilter += $@"(objectsid={IdentityInstance})";
                        }
                        else if (IdentityInstance.IsRegexMatch(@"^(CN|OU|DC)=.*"))
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                // and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf("DC=")).Replace("DC=", "").Replace(",", ".");
                                Logger.Write_Verbose($@"[Get-DomainObjectAcl] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                Searcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                                if (Searcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainObjectAcl] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
                        }
                        else if (IdentityInstance.IsRegexMatch(@"^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$"))
                        {
                            var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                            IdentityFilter += $@"(objectguid={GuidByteString})";
                        }
                        else if (IdentityInstance.Contains('.'))
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
                    Logger.Write_Verbose($@"[Get-DomainObjectAcl] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }

                if (Filter.IsNotNullOrEmpty())
                {
                    Searcher.Filter = $@"(&{Filter})";
                }
                Logger.Write_Verbose($@"[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: {Searcher.Filter}");

                var Results = Searcher.FindAll();
                foreach (SearchResult result in Results)
                {
                    var Object = result.Properties;

                    string ObjectSid = null;
                    if (Object["objectsid"] != null && Object["objectsid"].Count > 0 && Object["objectsid"][0] != null)
                    {
                        ObjectSid = new System.Security.Principal.SecurityIdentifier(Object["objectsid"][0] as byte[], 0).Value;
                    }
                    else
                    {
                        ObjectSid = null;
                    }

                    try
                    {
                        var rsd = new System.Security.AccessControl.RawSecurityDescriptor(Object["ntsecuritydescriptor"][0] as byte[], 0);
                        var rawAcl = args.Sacl ? rsd.SystemAcl : rsd.DiscretionaryAcl;
                        foreach (var ace in rawAcl)
                        {
                            var acl = new ACL { Ace = ace };
                            bool Continue = false;
                            if (args.RightsFilter != null)
                            {
                                string GuidFilter = null;
                                switch (args.RightsFilter.Value)
                                {
                                    case Rights.ResetPassword:
                                        GuidFilter = "00299570-246d-11d0-a768-00aa006e0529";
                                        break;
                                    case Rights.WriteMembers:
                                        GuidFilter = "bf9679c0-0de6-11d0-a285-00aa003049e2";
                                        break;
                                    default:
                                        GuidFilter = "00000000-0000-0000-0000-000000000000";
                                        break;
                                }
                                if (ace is System.Security.AccessControl.ObjectAccessRule)
                                {
                                    if (string.Compare(((object)ace as System.Security.AccessControl.ObjectAccessRule).ObjectType.ToString(), GuidFilter, StringComparison.OrdinalIgnoreCase) == 0)
                                    {
                                        acl.ObjectDN = Object["distinguishedname"][0] as string;
                                        acl.ObjectSID = ObjectSid;
                                        Continue = true;
                                    }
                                }
                            }
                            else
                            {
                                acl.ObjectDN = Object["distinguishedname"][0] as string;
                                acl.ObjectSID = ObjectSid;
                                Continue = true;
                            }
                            if (Continue)
                            {
                                if (ace is System.Security.AccessControl.KnownAce)
                                    acl.ActiveDirectoryRights = (System.DirectoryServices.ActiveDirectoryRights)(ace as System.Security.AccessControl.KnownAce).AccessMask;
                                if (GUIDs != null)
                                {
                                    // if we're resolving GUIDs, map them them to the resolved hash table
                                    if (ace is ObjectAce)
                                    {
                                        try { (acl.Ace as ObjectAce).ObjectAceType = new Guid(GUIDs[(ace as ObjectAce).ObjectAceType.ToString()]); }
                                        catch { }
                                        try { (acl.Ace as ObjectAce).InheritedObjectAceType = new Guid(GUIDs[(ace as ObjectAce).InheritedObjectAceType.ToString()]); }
                                        catch { }
                                    }
                                    else if (ace is ObjectAccessRule)
                                    {
                                        /*try { (acl.Ace as ObjectAccessRule).ObjectType = new Guid(GUIDs[(ace as ObjectAccessRule).ObjectType.ToString()]); }
                                        catch { }
                                        try { (acl.Ace as ObjectAccessRule).InheritedObjectType = new Guid(GUIDs[(ace as ObjectAccessRule).InheritedObjectType.ToString()]); }
                                        catch { }*/
                                    }
                                }

                                ACLs.Add(acl);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Get-DomainObjectAcl] Error: {e}");
                    }
                }
            }
            return ACLs;
        }

    }
}
