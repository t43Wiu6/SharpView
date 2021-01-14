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
    class NewDomainUser
    { 
        public static System.DirectoryServices.AccountManagement.UserPrincipal New_DomainUser(Args_New_DomainUser args = null)
        {
            if (args == null) args = new Args_New_DomainUser();

            var ContextArguments = new Args_Get_PrincipalContext
            {
                Identity = args.SamAccountName,
                Domain = args.Domain,
                Credential = args.Credential
            };
            var Context = GetPrincipalContext.Get_PrincipalContext(ContextArguments);

            if (Context != null)
            {
                var User = new System.DirectoryServices.AccountManagement.UserPrincipal(Context.Context);

                // set all the appropriate user parameters
                User.SamAccountName = Context.Identity;
                var TempCred = new System.Net.NetworkCredential("a", args.AccountPassword);
                User.SetPassword(TempCred.Password);
                User.Enabled = true;
                User.PasswordNotRequired = false;

                if (!string.IsNullOrEmpty(args.Name))
                {
                    User.Name = args.Name;
                }
                else
                {
                    User.Name = Context.Identity;
                }
                if (!string.IsNullOrEmpty(args.DisplayName))
                {
                    User.DisplayName = args.DisplayName;
                }
                else
                {
                    User.DisplayName = Context.Identity;
                }

                if (!string.IsNullOrEmpty(args.Description))
                {
                    User.Description = args.Description;
                }

                Logger.Write_Verbose($@"[New-DomainUser] Attempting to create user '{args.SamAccountName}'");
                try
                {
                    User.Save();
                    Logger.Write_Verbose($@"[New-DomainUser] User '{args.SamAccountName}' successfully created");
                    return User;
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[New-DomainUser] Error creating user '{args.SamAccountName}' : {e}");
                }
            }

            return null;
        }

    }
}
