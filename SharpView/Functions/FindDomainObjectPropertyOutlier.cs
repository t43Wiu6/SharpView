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
    class FindDomainObjectPropertyOutlier
    {
        public static IEnumerable<PropertyOutlier> Find_DomainObjectPropertyOutlier(Args_Find_DomainObjectPropertyOutlier args = null)
        {
            if (args == null) args = new Args_Find_DomainObjectPropertyOutlier();

            var UserReferencePropertySet = new[] { "admincount", "accountexpires", "badpasswordtime", "badpwdcount", "cn", "codepage", "countrycode", "description", "displayname", "distinguishedname", "dscorepropagationdata", "givenname", "instancetype", "iscriticalsystemobject", "lastlogoff", "lastlogon", "lastlogontimestamp", "lockouttime", "logoncount", "memberof", "msds-supportedencryptiontypes", "name", "objectcategory", "objectclass", "objectguid", "objectsid", "primarygroupid", "pwdlastset", "samaccountname", "samaccounttype", "sn", "useraccountcontrol", "userprincipalname", "usnchanged", "usncreated", "whenchanged", "whencreated" };

            var GroupReferencePropertySet = new[] { "admincount", "cn", "description", "distinguishedname", "dscorepropagationdata", "grouptype", "instancetype", "iscriticalsystemobject", "member", "memberof", "name", "objectcategory", "objectclass", "objectguid", "objectsid", "samaccountname", "samaccounttype", "systemflags", "usnchanged", "usncreated", "whenchanged", "whencreated" };

            var ComputerReferencePropertySet = new[] { "accountexpires", "badpasswordtime", "badpwdcount", "cn", "codepage", "countrycode", "distinguishedname", "dnshostname", "dscorepropagationdata", "instancetype", "iscriticalsystemobject", "lastlogoff", "lastlogon", "lastlogontimestamp", "localpolicyflags", "logoncount", "msds-supportedencryptiontypes", "name", "objectcategory", "objectclass", "objectguid", "objectsid", "operatingsystem", "operatingsystemservicepack", "operatingsystemversion", "primarygroupid", "pwdlastset", "samaccountname", "samaccounttype", "serviceprincipalname", "useraccountcontrol", "usnchanged", "usncreated", "whenchanged", "whencreated" };

            var SearcherArgumentsForUser = new Args_Get_DomainUser
            {
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var SearcherArgumentsForGroup = new Args_Get_DomainGroup
            {
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var SearcherArgumentsForComputer = new Args_Get_DomainComputer
            {
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            // Domain / Credential
            var TargetForest = string.Empty;
            if (!args.Domain.IsNullOrEmpty())
            {
                if (args.Credential != null)
                {
                    TargetForest = GetDomain.Get_Domain(new Args_Get_Domain { Domain = args.Domain }).Forest.Name;
                }
                else
                {
                    TargetForest = GetDomain.Get_Domain(new Args_Get_Domain { Domain = args.Domain, Credential = args.Credential }).Forest.Name;
                }
                Logger.Write_Verbose($@"[Find-DomainObjectPropertyOutlier] Enumerated forest '{TargetForest}' for target domain '{args.Domain}'");
            }

            var SchemaArguments = new
            {
                Credential = args.Credential,
                Forest = TargetForest
            };

            string[] ReferenceObjectProperties = null;
            ClassType? ReferenceObjectClass = null;
            if (args.ReferencePropertySet != null)
            {
                Logger.Write_Verbose(@"[Find-DomainObjectPropertyOutlier] Using specified -ReferencePropertySet");
                ReferenceObjectProperties = args.ReferencePropertySet;
            }
            else if (args.ReferenceObject != null)
            {
                Logger.Write_Verbose(@"[Find-DomainObjectPropertyOutlier] Extracting property names from -ReferenceObject to use as the reference property set");
                ReferenceObjectProperties = args.ReferenceObject.GetType().GetProperties().Select(x => x.Name).ToArray();
                ReferenceObjectClass = args.ReferenceObject.GetPropValue<ClassType>("objectclass");
                Logger.Write_Verbose($@"[Find-DomainObjectPropertyOutlier] Calculated ReferenceObjectClass : {ReferenceObjectClass}");
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainObjectPropertyOutlier] Using the default reference property set for the object class '{args.ClassName}'");
            }

            IEnumerable<object> Objects;
            if ((args.ClassName == ClassType.User) || (ReferenceObjectClass == ClassType.User))
            {
                Objects = GetDomainUser.Get_DomainUser(SearcherArgumentsForUser);
                if (ReferenceObjectProperties == null)
                {
                    ReferenceObjectProperties = UserReferencePropertySet;
                }
            }
            else if ((args.ClassName == ClassType.Group) || (ReferenceObjectClass == ClassType.Group))
            {
                Objects = GetDomainGroup.Get_DomainGroup(SearcherArgumentsForGroup);
                if (ReferenceObjectProperties == null)
                {
                    ReferenceObjectProperties = GroupReferencePropertySet;
                }
            }
            else if ((args.ClassName == ClassType.Computer) || (ReferenceObjectClass == ClassType.Computer))
            {
                Objects = GetDomainComputer.Get_DomainComputer(SearcherArgumentsForComputer);
                if (ReferenceObjectProperties == null)
                {
                    ReferenceObjectProperties = ComputerReferencePropertySet;
                }
            }
            else
            {
                throw new Exception($@"[Find-DomainObjectPropertyOutlier] Invalid class: {args.ClassName}");
            }

            var PropertyOutliers = new List<PropertyOutlier>();
            foreach (LDAPProperty Object in Objects)
            {
                var ObjectProperties = Object.GetType().GetProperties().Select(x => x.Name).ToArray();
                foreach (var ObjectProperty in ObjectProperties)
                {
                    var val = Object.GetPropValue<object>(ObjectProperty);
                    if (val is Dictionary<string, object>)
                    {
                        var dic = val as Dictionary<string, object>;
                        foreach (var ObjectProperty1 in dic.Keys)
                        {
                            if (!ReferenceObjectProperties.ContainsNoCase(ObjectProperty1))
                            {
                                var Out = new PropertyOutlier
                                {
                                    SamAccountName = Object.samaccountname,
                                    Property = ObjectProperty1,
                                    Value = dic[ObjectProperty1]
                                };
                                PropertyOutliers.Add(Out);
                            }
                        }
                    }
                    else if (val != null && !ReferenceObjectProperties.ContainsNoCase(ObjectProperty))
                    {
                        var Out = new PropertyOutlier
                        {
                            SamAccountName = Object.samaccountname,
                            Property = ObjectProperty,
                            Value = Object.GetPropValue<object>(ObjectProperty)
                        };
                        PropertyOutliers.Add(Out);
                    }
                }
            }

            return PropertyOutliers;
        }
    }
}
