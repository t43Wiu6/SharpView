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
    class InvokeUserImpersonation
    { 
        public static IntPtr Invoke_UserImpersonation(Args_Invoke_UserImpersonation args = null)
        {
            if (args == null) args = new Args_Invoke_UserImpersonation();

            if (System.Threading.Thread.CurrentThread.GetApartmentState() == System.Threading.ApartmentState.STA && !args.Quiet)
            {
                Logger.Write_Warning(@"[Invoke-UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work.");
            }

            IntPtr LogonTokenHandle;
            bool Result;
            if (args.TokenHandle != IntPtr.Zero)
            {
                LogonTokenHandle = args.TokenHandle;
            }
            else
            {
                LogonTokenHandle = IntPtr.Zero;
                var UserDomain = args.Credential.Domain;
                var UserName = args.Credential.UserName;
                Logger.Write_Warning($@"[Invoke-UserImpersonation] Executing LogonUser() with user: {UserDomain}\{UserName}");

                // LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3
                //   this is to simulate "runas.exe /netonly" functionality
                Result = NativeMethods.LogonUser(UserName, UserDomain, args.Credential.Password, LogonType.LOGON32_LOGON_NEW_CREDENTIALS, LogonProvider.LOGON32_PROVIDER_WINNT50, ref LogonTokenHandle);
                var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                if (!Result)
                {
                    throw new Exception($@"[Invoke-UserImpersonation] LogonUser() Error: {new System.ComponentModel.Win32Exception(LastError).Message}");
                }
            }

            // actually impersonate the token from LogonUser()
            Result = NativeMethods.ImpersonateLoggedOnUser(LogonTokenHandle);

            if (!Result)
            {
                throw new Exception($@"[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)");
            }


            Logger.Write_Verbose(@"[Invoke-UserImpersonation] Alternate credentials successfully impersonated");
            return LogonTokenHandle;
        }


    }
}
