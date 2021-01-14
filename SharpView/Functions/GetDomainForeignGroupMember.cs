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
    class GetDomainForeignGroupMember
    { 
        public static IEnumerable<ForeignGroupMember> Get_DomainForeignGroupMember(Args_Get_DomainForeignGroupMember args = null)
        {
            if (args == null) args = new Args_Get_DomainForeignGroupMember();

            var SearcherArguments = new Args_Get_DomainGroup
            {
                LDAPFilter = @"(member=*)",
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

            // standard group names to ignore
            var ExcludeGroups = new string[] { @"Users", @"Domain Users", @"Guests" };

            var ForeignGroupMembers = new List<ForeignGroupMember>();
            var Results = GetDomainGroup.Get_DomainGroup(SearcherArguments);
            Results = Results.Where(x => !ExcludeGroups.Contains((x as LDAPProperty).samaccountname));
            foreach (LDAPProperty result in Results)
            {
                var GroupName = result.samaccountname;
                var GroupDistinguishedName = result.distinguishedname;
                var GroupDomain = GroupDistinguishedName.Substring(GroupDistinguishedName.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");

                if (result.member != null)
                {
                    foreach (var item in result.member)
                    {
                        // filter for foreign SIDs in the cn field for users in another domain,
                        //   or if the DN doesn't end with the proper DN for the queried domain
                        var MemberDomain = item.Substring(item.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                        if (new Regex(@"CN=S-1-5-21.*-.*").Match(item).Success || GroupDomain != MemberDomain)
                        {
                            var MemberDistinguishedName = item;
                            var MemberName = item.Split(',')[0].Split('=')[1];

                            var ForeignGroupMember = new ForeignGroupMember
                            {
                                GroupDomain = GroupDomain,
                                GroupName = GroupName,
                                GroupDistinguishedName = GroupDistinguishedName,
                                MemberDomain = MemberDomain,
                                MemberName = MemberName,
                                MemberDistinguishedName = MemberDistinguishedName
                            };
                        }
                    }
                }
            }
            return ForeignGroupMembers;
        }

    }
}
