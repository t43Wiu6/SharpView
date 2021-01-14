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
    class GetNetLocalGroup
    { 
        public static IEnumerable<object> Get_NetLocalGroup(Args_Get_NetLocalGroup args = null)
        {
            if (args == null) args = new Args_Get_NetLocalGroup();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }

            var LocalGroups = new List<object>();

            foreach (var Computer in args.ComputerName)
            {
                if (args.Method == MethodType.API)
                {
                    // if we're using the Netapi32 NetLocalGroupEnum API call to get the local group information
                    // arguments for NetLocalGroupEnum
                    var QueryLevel = 1;
                    var PtrInfo = IntPtr.Zero;
                    var EntriesRead = 0;
                    var TotalRead = 0;
                    var ResumeHandle = 0;

                    // get the local user information
                    var Result = NativeMethods.NetLocalGroupEnum(Computer, QueryLevel, out PtrInfo, MAX_PREFERRED_LENGTH, out EntriesRead, out TotalRead, ref ResumeHandle);

                    // locate the offset of the initial intPtr
                    var Offset = PtrInfo.ToInt64();

                    // 0 = success
                    if ((Result == 0) && (Offset > 0))
                    {
                        // Work out how much to increment the pointer by finding out the size of the structure
                        var Increment = Marshal.SizeOf(typeof(LOCALGROUP_INFO_1));

                        // parse all the result structures
                        for (var i = 0; (i < EntriesRead); i++)
                        {
                            // create a new int ptr at the given offset and cast the pointer as our result structure
                            var NewIntPtr = new System.IntPtr(Offset);
                            var Info = (LOCALGROUP_INFO_1)Marshal.PtrToStructure(NewIntPtr, typeof(LOCALGROUP_INFO_1));

                            LocalGroups.Add(new LocalGroupAPI
                            {
                                ComputerName = Computer,
                                GroupName = Info.lgrpi1_name,
                                Comment = Info.lgrpi1_comment
                            });
                            Offset = NewIntPtr.ToInt64();
                            Offset += Increment;
                        }
                        // free up the result buffer
                        NativeMethods.NetApiBufferFree(PtrInfo);
                    }
                    else
                    {
                        Logger.Write_Verbose($@"[Get-NetLocalGroup] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                    }
                }
                else
                {
                    // otherwise we're using the WinNT service provider
                    var ComputerProvider = new System.DirectoryServices.DirectoryEntry($@"WinNT://{Computer},computer");
                    foreach (System.DirectoryServices.DirectoryEntry LocalGroup in ComputerProvider.Children)
                    {
                        if (LocalGroup.SchemaClassName.Equals("group", StringComparison.OrdinalIgnoreCase))
                        {
                            var Group = new LocalGroupWinNT
                            {
                                ComputerName = Computer,
                                GroupName = LocalGroup.Name,
                                SID = new System.Security.Principal.SecurityIdentifier((byte[])LocalGroup.InvokeGet("objectsid"), 0).Value,
                                Comment = LocalGroup.InvokeGet("Description").ToString()
                            };
                            LocalGroups.Add(Group);
                        }
                    }
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return LocalGroups;
        }

    }
}
