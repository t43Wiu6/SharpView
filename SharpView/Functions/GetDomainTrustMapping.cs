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
    class GetDomainTrustMapping
    { 
        public static IEnumerable<IDomainTrust> Get_DomainTrustMapping(Args_Get_DomainTrustMapping args = null)
        {
            if (args == null) args = new Args_Get_DomainTrustMapping();

            // keep track of domains seen so we don't hit infinite recursion
            var SeenDomains = new Dictionary<string, string>();

            // our domain status tracker
            var Domains = new System.Collections.Stack();

            var DomainTrustArguments = new Args_Get_DomainTrust
            {
                API = args.API,
                NET = args.NET,
                LDAPFilter = args.LDAPFilter,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            // get the current domain and push it onto the stack
            string CurrentDomain = null;
            if (args.Credential != null)
            {
                CurrentDomain = GetDomain.Get_Domain(new Args_Get_Domain { Credential = args.Credential }).Name;
            }
            else
            {
                CurrentDomain = GetDomain.Get_Domain().Name;
            }
            Domains.Push(CurrentDomain);

            var DomainTrustMappings = new List<IDomainTrust>();
            while (Domains.Count != 0)
            {

                string Domain = Domains.Pop() as string;

                // if we haven't seen this domain before
                if (Domain != null && Domain.Trim() != @"" && !SeenDomains.ContainsKey(Domain))
                {

                    Logger.Write_Verbose($@"[Get-DomainTrustMapping] Enumerating trusts for domain: '{Domain}'");

                    // mark it as seen in our list
                    SeenDomains.Add(Domain, "");

                    try
                    {
                        // get all the trusts for this domain
                        DomainTrustArguments.Domain = Domain;
                        var Trusts = GetDomainTrust.Get_DomainTrust(DomainTrustArguments);

                        // get any forest trusts, if they exist
                        if (args.NET)
                        {
                            var ForestTrustArguments = new Args_Get_Forest
                            {
                                Forest = args.Forest,
                                Credential = args.Credential
                            };
                            Trusts.Union(GetForestTrust.Get_ForestTrust(ForestTrustArguments));
                        }

                        if (Trusts != null)
                        {
                            // enumerate each trust found
                            foreach (var Trust in Trusts)
                            {
                                if (Trust.SourceName.IsNotNullOrEmpty() && Trust.TargetName.IsNotNullOrEmpty())
                                {
                                    // make sure we process the target
                                    Domains.Push(Trust.TargetName);
                                    DomainTrustMappings.Add(Trust);
                                }
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Get-DomainTrustMapping] Error: {e}");
                    }
                }
            }
            return DomainTrustMappings;
        }

    }
}
