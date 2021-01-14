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
    class TestAdminAccess
    { 
        public static IEnumerable<AdminAccess> Test_AdminAccess(Args_Test_AdminAccess args = null)
        {
            if (args == null) args = new Args_Test_AdminAccess();

            IntPtr LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation { Credential = args.Credential });
            }

            var IsAdmins = new List<AdminAccess>();
            foreach (var Computer in args.ComputerName)
            {
                // 0xF003F - SC_MANAGER_ALL_ACCESS
                // http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                var Handle = NativeMethods.OpenSCManagerW($@"\\{Computer}", "ServicesActive", 0xF003F);
                var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                var IsAdmin = new AdminAccess
                {
                    ComputerName = Computer
                };

                // if we get a non-zero handle back, everything was successful
                if (Handle != IntPtr.Zero)
                {
                    NativeMethods.CloseServiceHandle(Handle);
                    IsAdmin.IsAdmin = true;
                }
                else
                {
                    Logger.Write_Verbose($@"[Test-AdminAccess] Error: {new System.ComponentModel.Win32Exception((int)LastError).Message}");
                    IsAdmin.IsAdmin = false;
                }
                IsAdmins.Add(IsAdmin);
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }

            return IsAdmins;
        }

    }
}
