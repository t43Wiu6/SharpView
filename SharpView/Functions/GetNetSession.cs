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
    class GetNetSession
    { 
        public static IEnumerable<SessionInfo> Get_NetSession(Args_Get_NetSession args = null)
        {
            if (args == null) args = new Args_Get_NetSession();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }

            var SessionInfos = new List<SessionInfo>();
            foreach (var Computer in args.ComputerName)
            {
                // arguments for NetSessionEnum
                var QueryLevel = 10;
                var PtrInfo = IntPtr.Zero;
                var EntriesRead = 0;
                var TotalRead = 0;
                var ResumeHandle = 0;
                var UserName = string.Empty;

                // get session information
                var Result = NativeMethods.NetSessionEnum(Computer, string.Empty, UserName, QueryLevel, out PtrInfo, -1, ref EntriesRead, ref TotalRead, ref ResumeHandle);

                // locate the offset of the initial intPtr
                var Offset = PtrInfo.ToInt64();

                // 0 = success
                if ((Result == 0) && (Offset > 0))
                {
                    // work out how much to increment the pointer by finding out the size of the structure
                    var Increment = Marshal.SizeOf(typeof(SESSION_INFO_10));

                    // parse all the result structures
                    for (var i = 0; (i < EntriesRead); i++)
                    {
                        // create a new int ptr at the given offset and cast the pointer as our result structure
                        var NewIntPtr = new System.IntPtr(Offset);
                        var Info = (SESSION_INFO_10)Marshal.PtrToStructure(NewIntPtr, typeof(SESSION_INFO_10));

                        // return all the sections of the structure - have to do it this way for V2
                        var Session = new SessionInfo
                        {
                            ComputerName = Computer,
                            CName = Info.sesi10_cname,
                            UserName = Info.sesi10_username,
                            Time = Info.sesi502_time,
                            IdleTime = Info.sesi502_idle_time
                        };
                        Offset = NewIntPtr.ToInt64();
                        Offset += Increment;
                        SessionInfos.Add(Session);
                    }

                    // free up the result buffer
                    NativeMethods.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-NetSession] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return SessionInfos;
        }

    }
}
