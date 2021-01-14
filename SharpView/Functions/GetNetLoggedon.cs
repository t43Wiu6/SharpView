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
    class GetNetLoggedon
    { 
        public static IEnumerable<LoggedOnUserInfo> Get_NetLoggedon(Args_Get_NetLoggedon args = null)
        {
            if (args == null) args = new Args_Get_NetLoggedon();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }

            var LoggedOns = new List<LoggedOnUserInfo>();

            foreach (var Computer in args.ComputerName)
            {
                // declare the reference variables
                var QueryLevel = 1;
                var PtrInfo = IntPtr.Zero;
                var EntriesRead = 0;
                var TotalRead = 0;
                var ResumeHandle = 0;

                // get logged on user information
                var Result = NativeMethods.NetWkstaUserEnum(Computer, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ref ResumeHandle);

                // locate the offset of the initial intPtr
                var Offset = PtrInfo.ToInt64();

                // 0 = success
                if ((Result == 0) && (Offset > 0))
                {
                    // work out how much to increment the pointer by finding out the size of the structure
                    var Increment = Marshal.SizeOf(typeof(WKSTA_USER_INFO_1));

                    // parse all the result structures
                    for (var i = 0; (i < EntriesRead); i++)
                    {
                        // create a new int ptr at the given offset and cast the pointer as our result structure
                        var NewIntPtr = new System.IntPtr(Offset);
                        var Info = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(NewIntPtr, typeof(WKSTA_USER_INFO_1));

                        // return all the sections of the structure - have to do it this way for V2
                        LoggedOns.Add(new LoggedOnUserInfo
                        {
                            UserName = Info.wkui1_username,
                            LogonDomain = Info.wkui1_logon_domain,
                            AuthDomains = Info.wkui1_oth_domains,
                            LogonServer = Info.wkui1_logon_server,
                            ComputerName = Computer
                        });
                        Offset = NewIntPtr.ToInt64();
                        Offset += Increment;
                    }

                    // free up the result buffer
                    NativeMethods.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-NetLoggedon] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return LoggedOns;
        }


    }
}
