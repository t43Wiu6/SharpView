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
    class GetNetRDPSession
    { 
        public static IEnumerable<RDPSessionInfo> Get_NetRDPSession(Args_Get_NetRDPSession args = null)
        {
            if (args == null) args = new Args_Get_NetRDPSession();

            IntPtr LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation { Credential = args.Credential });
            }

            var RDPSessions = new List<RDPSessionInfo>();
            foreach (var Computer in args.ComputerName)
            {

                // open up a handle to the Remote Desktop Session host
                var Handle = NativeMethods.WTSOpenServerEx(Computer);

                // if we get a non-zero handle back, everything was successful
                if (Handle != IntPtr.Zero)
                {
                    // arguments for WTSEnumerateSessionsEx
                    var ppSessionInfo = IntPtr.Zero;
                    UInt32 pCount = 0;

                    // get information on all current sessions
                    UInt32 level = 1;
                    var Result = NativeMethods.WTSEnumerateSessionsEx(Handle, ref level, 0, ref ppSessionInfo, ref pCount);
                    var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                    // locate the offset of the initial intPtr
                    var Offset = ppSessionInfo.ToInt64();

                    if ((Result != 0) && (Offset > 0))
                    {

                        // work out how much to increment the pointer by finding out the size of the structure
                        var Increment = Marshal.SizeOf(typeof(NativeMethods.WTS_SESSION_INFO_1));

                        // parse all the result structures
                        for (var i = 0; (i < pCount); i++)
                        {

                            // create a new int ptr at the given offset and cast the pointer as our result structure
                            var NewIntPtr = new IntPtr(Offset);
                            var Info = (NativeMethods.WTS_SESSION_INFO_1)Marshal.PtrToStructure(NewIntPtr, typeof(NativeMethods.WTS_SESSION_INFO_1));

                            var RDPSession = new RDPSessionInfo();

                            if (Info.pHostName != null)
                            {
                                RDPSession.ComputerName = Info.pHostName;
                            }
                            else
                            {
                                // if no hostname returned, use the specified hostname
                                RDPSession.ComputerName = Computer;
                            }

                            RDPSession.SessionName = Info.pSessionName;

                            if ((Info.pDomainName == null) || (Info.pDomainName == ""))
                            {
                                // if a domain isn't returned just use the username
                                RDPSession.UserName = Info.pUserName;
                            }
                            else
                            {
                                RDPSession.UserName = $@"{Info.pDomainName}\{Info.pUserName}";
                            }

                            RDPSession.ID = Info.SessionId;
                            RDPSession.State = Info.State;

                            var ppBuffer = IntPtr.Zero;
                            uint pBytesReturned = 0;

                            // query for the source client IP with WTSQuerySessionInformation
                            // https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx
                            var Result2 = NativeMethods.WTSQuerySessionInformation(Handle, Info.SessionId, NativeMethods.WTS_INFO_CLASS.WTSClientAddress, out ppBuffer, out pBytesReturned);
                            var LastError2 = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                            if (Result2 == false)
                            {
                                Logger.Write_Verbose($@"[Get-NetRDPSession] Error: {new System.ComponentModel.Win32Exception((int)LastError2).Message}");
                            }
                            else
                            {
                                var Offset2 = ppBuffer.ToInt64();
                                var NewIntPtr2 = new IntPtr(Offset2);
                                var Info2 = (NativeMethods.WTS_CLIENT_ADDRESS)Marshal.PtrToStructure(NewIntPtr2, typeof(NativeMethods.WTS_CLIENT_ADDRESS));

                                string SourceIP;
                                if (Info2.Address[2] != 0)
                                {
                                    SourceIP = $@"{Info2.Address[2]}.{Info2.Address[3]}.{Info2.Address[4]}.{Info2.Address[5]}";
                                }
                                else
                                {
                                    SourceIP = null;
                                }

                                RDPSession.SourceIP = SourceIP;
                                RDPSessions.Add(RDPSession);

                                // free up the memory buffer
                                NativeMethods.WTSFreeMemory(ppBuffer);

                                Offset += Increment;
                            }
                        }
                        // free up the memory result buffer
                        NativeMethods.WTSFreeMemoryEx(WTS_TYPE_CLASS.WTSTypeSessionInfoLevel1, ppSessionInfo, pCount);
                    }
                    else
                    {
                        Logger.Write_Verbose($@"[Get-NetRDPSession] Error: {new System.ComponentModel.Win32Exception((int)LastError).Message}");
                    }
                    // close off the service handle
                    NativeMethods.WTSCloseServer(Handle);
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-NetRDPSession] Error opening the Remote Desktop Session Host (RD Session Host) server for: {Computer}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }

            return RDPSessions;
        }

    }
}
