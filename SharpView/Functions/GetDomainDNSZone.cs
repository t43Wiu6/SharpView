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
    class GetDomainDNSZone
    { 
        public static IEnumerable<DNSZone> Get_DomainDNSZone(Args_Get_DomainDNSZone args = null)
        {
            if (args == null) args = new Args_Get_DomainDNSZone();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                LDAPFilter = @"(objectClass=dnsZone)",
                Domain = args.Domain,
                Server = args.Server,
                Properties = args.Properties,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Credential = args.Credential
            };
            var DNSSearcher1 = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);

            SearchResult[] Results = null;
            List<DNSZone> Outs = null;
            if (DNSSearcher1 != null)
            {
                if (args.FindOne) { Results = new SearchResult[] { DNSSearcher1.FindOne() }; }
                else
                {
                    var items = DNSSearcher1.FindAll();
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
                        var Out = new DNSZone(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                        Outs.Add(Out);
                    }
                }
                DNSSearcher1.Dispose();
            }

            SearcherArguments.SearchBasePrefix = @"CN=MicrosoftDNS,DC=DomainDnsZones";
            var DNSSearcher2 = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);

            if (DNSSearcher2 != null)
            {
                try
                {
                    if (args.FindOne) { Results = new SearchResult[] { DNSSearcher2.FindOne() }; }
                    else
                    {
                        var items = DNSSearcher2.FindAll();
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
                            var Out = new DNSZone(ConvertLDAPProperty.Convert_LDAPProperty(result.Properties));
                            Outs.Add(Out);
                        }
                    }
                }
                catch
                {
                    Logger.Write_Verbose(@"[Get-DomainDNSZone] Error accessing 'CN=MicrosoftDNS,DC=DomainDnsZones'");
                }
                DNSSearcher2.Dispose();
            }
            return Outs;
        }

    }
}
