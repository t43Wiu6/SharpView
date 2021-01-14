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
    class AddDomainObjectAcl
    { 
        public static void Add_DomainObjectAcl(Args_Add_DomainObjectAcl args = null)
        {
            if (args == null) args = new Args_Add_DomainObjectAcl();

            var TargetSearcherArguments = new Args_Get_DomainObject
            {
                Properties = new[] { "distinguishedname" },
                Raw = true,
                Domain = args.TargetDomain,
                LDAPFilter = args.TargetLDAPFilter,
                SearchBase = args.TargetSearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var PrincipalSearcherArguments = new Args_Get_DomainObject
            {
                Identity = args.PrincipalIdentity,
                Properties = new[] { "distinguishedname", "objectsid" },
                Domain = args.PrincipalDomain,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var Principals = GetDomainObject.Get_DomainObject(PrincipalSearcherArguments);
            if (Principals == null)
            {
                throw new Exception($@"Unable to resolve principal: {args.PrincipalIdentity}");
            }

            TargetSearcherArguments.Identity = args.TargetIdentity;
            var Targets = GetDomainObject.Get_DomainObject(TargetSearcherArguments);

            foreach (SearchResult TargetObject in Targets)
            {
                var InheritanceType = System.DirectoryServices.ActiveDirectorySecurityInheritance.None;
                var ControlType = System.Security.AccessControl.AccessControlType.Allow;
                var ACEs = new List<System.DirectoryServices.ActiveDirectoryAccessRule>();

                var GUIDs = new List<string>();
                if (args.RightsGUID != null)
                {
                    GUIDs.Add(args.RightsGUID.ToString());
                }
                else
                {
                    switch (args.Rights)
                    {
                        // ResetPassword doesn't need to know the user's current password
                        case Rights.ResetPassword:
                            GUIDs.Add("00299570-246d-11d0-a768-00aa006e0529");
                            break;
                        // allows for the modification of group membership
                        case Rights.WriteMembers:
                            GUIDs.Add("bf9679c0 -0de6-11d0-a285-00aa003049e2");
                            break;
                        // 'DS-Replication-Get-Changes' = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                        // 'DS-Replication-Get-Changes-All' = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                        // 'DS-Replication-Get-Changes-In-Filtered-Set' = 89e95b76-444d-4c62-991a-0facbeda640c
                        // when applied to a domain's ACL, allows for the use of DCSync
                        case Rights.DCSync:
                            GUIDs.Add("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
                            GUIDs.Add("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
                            GUIDs.Add("89e95b76-444d-4c62-991a-0facbeda640c");
                            break;
                    }
                }

                foreach (LDAPProperty PrincipalObject in Principals)
                {
                    Logger.Write_Verbose($@"[Add-DomainObjectAcl] Granting principal {PrincipalObject.distinguishedname} '{args.Rights}' on {TargetObject.Properties["distinguishedname"][0]}");

                    try
                    {
                        var Identity = new System.Security.Principal.SecurityIdentifier(PrincipalObject.objectsid[0]);

                        if (GUIDs != null)
                        {
                            foreach (var GUID in GUIDs)
                            {
                                var NewGUID = new Guid(GUID);
                                var ADRights = System.DirectoryServices.ActiveDirectoryRights.ExtendedRight;
                                ACEs.Add(new System.DirectoryServices.ActiveDirectoryAccessRule(Identity, ADRights, ControlType, NewGUID, InheritanceType));
                            }
                        }
                        else
                        {
                            // deault to GenericAll rights
                            var ADRights = System.DirectoryServices.ActiveDirectoryRights.GenericAll;
                            ACEs.Add(new System.DirectoryServices.ActiveDirectoryAccessRule(Identity, ADRights, ControlType, InheritanceType));
                        }

                        // add all the new ACEs to the specified object directory entry
                        foreach (var ACE in ACEs)
                        {
                            Logger.Write_Verbose($@"[Add-DomainObjectAcl] Granting principal {PrincipalObject.distinguishedname} rights GUID '{ACE.ObjectType}' on {TargetObject.Properties["distinguishedname"][0]}");
                            var TargetEntry = TargetObject.GetDirectoryEntry();
                            TargetEntry.Options.SecurityMasks = SecurityMasks.Dacl;
                            TargetEntry.ObjectSecurity.AddAccessRule(ACE);
                            TargetEntry.CommitChanges();
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Add-DomainObjectAcl] Error granting principal {PrincipalObject.distinguishedname} '{args.Rights}' on {TargetObject.Properties["distinguishedname"][0]}: {e}");
                    }
                }
            }
        }

    }
}
