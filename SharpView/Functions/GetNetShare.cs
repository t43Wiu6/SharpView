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
    class GetNetShare
    { 
        public static IEnumerable<ShareInfo> Get_NetShare(Args_Get_NetShare args = null)
        {
            if (args == null) args = new Args_Get_NetShare();

            var shareInfos = new List<ShareInfo>();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }
            foreach (var Computer in args.ComputerName)
            {
                // arguments for NetShareEnum
                var QueryLevel = 1;
                var PtrInfo = IntPtr.Zero;
                var EntriesRead = 0;
                var TotalRead = 0;
                var ResumeHandle = 0;

                // get the raw share information
                var Result = NativeMethods.NetShareEnum(Computer, QueryLevel, ref PtrInfo, MAX_PREFERRED_LENGTH, ref EntriesRead, ref TotalRead, ref ResumeHandle);

                // locate the offset of the initial intPtr
                var Offset = PtrInfo.ToInt64();

                // 0 = success
                if ((Result == 0) && (Offset > 0))
                {
                    // work out how much to increment the pointer by finding out the size of the structure
                    var Increment = Marshal.SizeOf(typeof(SHARE_INFO_1));

                    // parse all the result structures
                    for (var i = 0; (i < EntriesRead); i++)
                    {
                        // create a new int ptr at the given offset and cast the pointer as our result structure
                        var NewIntPtr = new System.IntPtr(Offset);
                        var Info = (SHARE_INFO_1)Marshal.PtrToStructure(NewIntPtr, typeof(SHARE_INFO_1));

                        // return all the sections of the structure - have to do it this way for V2
                        shareInfos.Add(new ShareInfo
                        {
                            Name = Info.shi1_netname,
                            Type = Info.shi1_type,
                            Remark = Info.shi1_remark,
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
                    Logger.Write_Verbose($@"[Get-NetShare] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return shareInfos;
        }

    }
}
