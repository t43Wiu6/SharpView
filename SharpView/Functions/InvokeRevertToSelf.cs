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
    class InvokeRevertToSelf
    { 
        public static void Invoke_RevertToSelf(IntPtr TokenHandle)
        {
            var Result = false;
            if (TokenHandle != IntPtr.Zero)
            {
                Logger.Write_Warning(@"[Invoke-RevertToSelf] Reverting token impersonation and closing LogonUser() token handle");
                Result = NativeMethods.CloseHandle(TokenHandle);
            }

            Result = NativeMethods.RevertToSelf();
            var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

            if (!Result)
            {
                throw new Exception($@"[Invoke-RevertToSelf] RevertToSelf() Error: {new System.ComponentModel.Win32Exception(LastError).Message}");
            }

            Logger.Write_Verbose(@"[Invoke-RevertToSelf] Token impersonation successfully reverted");
        }


    }
}
