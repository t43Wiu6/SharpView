using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.DirectoryServices.ActiveDirectory;
using SharpView.Arguments;
using SharpView.Returns;
using SharpView.Enums;
using SharpView.Utils;

namespace SharpView.Functions
{ 
    class GetLocalUser
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct USER_INFO_0
        {
            public string UserName;
        }

        [DllImport("Netapi32.dll")]
        extern static int NetUserEnum(
             [MarshalAs(UnmanagedType.LPWStr)]
             string servername,
             int level,
             int filter,
             out IntPtr bufptr,
             int prefmaxlen,
             out int entriesread,
             out int totalentries,
             out int resume_handle);

        [DllImport("Netapi32.dll")]
        extern static int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Advapi32.dll", EntryPoint = "GetUserName", ExactSpelling = false, SetLastError = true)]
        static extern bool GetUserName(
        [MarshalAs(UnmanagedType.LPArray)] byte[] lpBuffer,
        [MarshalAs(UnmanagedType.LPArray)] Int32[] nSize);

        public static List<string> Get_LocalUser(Args_Get_DomainUser args = null)
        {
            List<string> users = new List<string>();
            int EntriesRead;
            int TotalEntries;
            int Resume;
            IntPtr bufPtr;

            NetUserEnum(null, 0, 2, out bufPtr, -1, out EntriesRead, out TotalEntries, out Resume);

            if (EntriesRead > 0)
            {
                Logger.Write_Output("[Get-LocalUser] Found "+ EntriesRead + " user.");
                USER_INFO_0[] Users = new USER_INFO_0[EntriesRead];
                IntPtr iter = bufPtr;
                for (int i = 0; i < EntriesRead; i++)
                {
                    Users[i] = (USER_INFO_0)Marshal.PtrToStructure(iter, typeof(USER_INFO_0));
                    iter = (IntPtr)((int)iter + Marshal.SizeOf(typeof(USER_INFO_0)));
                    users.Add(Users[i].UserName);
                }
                NetApiBufferFree(bufPtr);
            }
            else
            {
                Logger.Write_Warning("[Get-LocalUser] Error, Cann't found any user.");
            }
            return users;
        }

    }
}
