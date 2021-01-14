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
    class NewDomainGroup
    { 
        public static System.DirectoryServices.AccountManagement.GroupPrincipal New_DomainGroup(Args_New_DomainGroup args = null)
        {
            if (args == null) args = new Args_New_DomainGroup();

            var ContextArguments = new Args_Get_PrincipalContext
            {
                Identity = args.SamAccountName,
                Domain = args.Domain,
                Credential = args.Credential
            };
            var Context = GetPrincipalContext.Get_PrincipalContext(ContextArguments);

            if (Context != null)
            {
                var Group = new System.DirectoryServices.AccountManagement.GroupPrincipal(Context.Context);

                // set all the appropriate group parameters
                Group.SamAccountName = Context.Identity;

                if (!string.IsNullOrEmpty(args.Name))
                {
                    Group.Name = args.Name;
                }
                else
                {
                    Group.Name = Context.Identity;
                }
                if (!string.IsNullOrEmpty(args.DisplayName))
                {
                    Group.DisplayName = args.DisplayName;
                }
                else
                {
                    Group.DisplayName = Context.Identity;
                }

                if (!string.IsNullOrEmpty(args.Description))
                {
                    Group.Description = args.Description;
                }

                Logger.Write_Verbose($@"[New-DomainGroup] Attempting to create group '{args.SamAccountName}'");
                try
                {
                    Group.Save();
                    Logger.Write_Verbose($@"[New-DomainGroup] Group '{args.SamAccountName}' successfully created");
                    return Group;
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[New-DomainGroup] Error creating group '{args.SamAccountName}' : {e}");
                }
            }

            return null;
        }

    }
}
