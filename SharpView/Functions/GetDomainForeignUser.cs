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
    class GetDomainForeignUser
    { 
        public static IEnumerable<ForeignUser> Get_DomainForeignUser(Args_Get_DomainForeignUser args = null)
        {
            if (args == null) args = new Args_Get_DomainForeignUser();

            var SearcherArguments = new Args_Get_DomainUser
            {
                LDAPFilter = @"(memberof=*)",
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

            var ForeignUsers = new List<ForeignUser>();
            var Results = GetDomainUser.Get_DomainUser(SearcherArguments);
            foreach (LDAPProperty result in Results)
            {
                foreach (var Membership in result.memberof)
                {
                    var Index = Membership.IndexOf(@"DC=");
                    if (Index != 0)
                    {
                        var GroupDomain = Membership.Substring(Index).Replace(@"DC=", @"").Replace(@",", @".");
                        var UserDistinguishedName = result.distinguishedname;
                        var UserIndex = UserDistinguishedName.IndexOf(@"DC=");
                        var UserDomain = result.distinguishedname.Substring(UserIndex).Replace(@"DC=", @"").Replace(@",", @".");

                        if (GroupDomain != UserDomain)
                        {
                            // if the group domain doesn't match the user domain, display it
                            var GroupName = Membership.Split(',')[0].Split('=')[1];
                            var ForeignUser = new ForeignUser
                            {
                                UserDomain = UserDomain,
                                UserName = result.samaccountname,
                                UserDistinguishedName = result.distinguishedname,
                                GroupDomain = GroupDomain,
                                GroupName = GroupName,
                                GroupDistinguishedName = Membership
                            };
                        }
                    }
                }
            }
            return ForeignUsers;
        }

    }
}
