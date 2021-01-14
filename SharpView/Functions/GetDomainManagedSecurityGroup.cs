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
    class GetDomainManagedSecurityGroup
    { 
        public static IEnumerable<ManagedSecurityGroup> Get_DomainManagedSecurityGroup(Args_Get_DomainManagedSecurityGroup args = null)
        {
            if (args == null) args = new Args_Get_DomainManagedSecurityGroup();

            var SearcherArguments = new Args_Get_DomainGroup
            {
                LDAPFilter = @"(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))",
                Properties = new[] { @"distinguishedName", @"managedBy", @"samaccounttype", @"samaccountname" },
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ObjectArguments = new Args_Get_DomainObject
            {
                LDAPFilter = @"(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))",
                Properties = new[] { @"distinguishedName", @"managedBy", @"samaccounttype", @"samaccountname" },
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            string TargetDomain = null;
            if (args.Domain.IsNotNullOrEmpty())
            {
                SearcherArguments.Domain = args.Domain;
                TargetDomain = args.Domain;
            }
            else
            {
                TargetDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            }

            var ManagedGroups = new List<ManagedSecurityGroup>();
            // go through the list of security groups on the domain and identify those who have a manager
            var groups = GetDomainGroup.Get_DomainGroup(SearcherArguments);
            foreach (LDAPProperty group in groups)
            {
                ObjectArguments.Properties = new[] { @"distinguishedname", @"name", @"samaccounttype", @"samaccountname", @"objectsid" };
                ObjectArguments.Identity = new[] { group.managedby };
                SearcherArguments.LDAPFilter = null;

                // $SearcherArguments
                // retrieve the object that the managedBy DN refers to
                var GroupManager = GetDomainObject.Get_DomainObject(ObjectArguments).First() as LDAPProperty;
                // Write-Host "GroupManager: $GroupManager"
                var ManagedGroup = new ManagedSecurityGroup
                {
                    GroupName = group.samaccountname,
                    GroupDistinguishedName = group.distinguishedname,
                    ManagerName = GroupManager.samaccountname,
                    ManagerDistinguishedName = GroupManager.distinguishedname
                };

                // determine whether the manager is a user or a group
                if (GroupManager.samaccounttype == SamAccountType.GROUP_OBJECT)
                {
                    ManagedGroup.ManagerType = ManagerType.Group;
                }
                else if (GroupManager.samaccounttype == SamAccountType.USER_OBJECT)
                {
                    ManagedGroup.ManagerType = ManagerType.User;
                }

                ManagedGroup.ManagerCanWrite = "UNKNOWN";
                ManagedGroups.Add(ManagedGroup);
            }

            return ManagedGroups;
        }

    }
}
