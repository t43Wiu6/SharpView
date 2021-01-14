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
    class SetDomainUserPassword
    { 
        public static void Set_DomainUserPassword(Args_Set_DomainUserPassword args = null)
        {
            if (args == null) args = new Args_Set_DomainUserPassword();

            var ContextArguments = new Args_Get_PrincipalContext
            {
                Identity = args.Identity,
                Domain = args.Domain,
                Credential = args.Credential
            };
            var Context = GetPrincipalContext.Get_PrincipalContext(ContextArguments);

            System.DirectoryServices.AccountManagement.UserPrincipal User = null;
            if (Context != null)
            {
                User = System.DirectoryServices.AccountManagement.UserPrincipal.FindByIdentity(Context.Context, args.Identity);

                if (User != null)
                {
                    Logger.Write_Verbose($@"[Set-DomainUserPassword] Attempting to set the password for user '{args.Identity}'");
                    try
                    {
                        var TempCred = new System.Net.NetworkCredential("a", args.AccountPassword);
                        User.SetPassword(TempCred.Password);
                        User.Save();
                        Logger.Write_Verbose($@"[Set-DomainUserPassword] Password for user '{args.Identity}' successfully reset");
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Set-DomainUserPassword] Error setting password for user '{args.Identity}' : {e}");
                    }
                }
                else
                {
                    Logger.Write_Warning($@"[Set-DomainUserPassword] Unable to find user '{args.Identity}'");
                }
            }
        }

    }
}
