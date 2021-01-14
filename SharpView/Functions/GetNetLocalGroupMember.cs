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
    class GetNetLocalGroupMember
    { 
        public static IEnumerable<object> Get_NetLocalGroupMember(Args_Get_NetLocalGroupMember args = null)
        {
            if (args == null) args = new Args_Get_NetLocalGroupMember();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }

            var LocalGroupMembers = new List<object>();

            foreach (var Computer in args.ComputerName)
            {
                if (args.Method == MethodType.API)
                {
                    // if we're using the Netapi32 NetLocalGroupGetMembers API call to get the local group information
                    // arguments for NetLocalGroupGetMembers
                    var QueryLevel = 2;
                    var PtrInfo = IntPtr.Zero;
                    var EntriesRead = 0;
                    var TotalRead = 0;
                    var ResumeHandle = IntPtr.Zero;

                    // get the local user information
                    var Result = NativeMethods.NetLocalGroupGetMembers(Computer, args.GroupName, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ResumeHandle);

                    // locate the offset of the initial intPtr
                    var Offset = PtrInfo.ToInt64();

                    var Members = new List<object>();

                    // 0 = success
                    if ((Result == 0) && (Offset > 0))
                    {
                        // Work out how much to increment the pointer by finding out the size of the structure
                        var Increment = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2));

                        // parse all the result structures
                        for (var i = 0; (i < EntriesRead); i++)
                        {
                            // create a new int ptr at the given offset and cast the pointer as our result structure
                            var NewIntPtr = new System.IntPtr(Offset);
                            var Info = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(NewIntPtr, typeof(LOCALGROUP_MEMBERS_INFO_2));

                            Offset = NewIntPtr.ToInt64();
                            Offset += Increment;

                            var SidString = "";
                            var Result2 = NativeMethods.ConvertSidToStringSid(Info.lgrmi2_sid, out SidString);
                            var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                            if (!Result2)
                            {
                                Logger.Write_Verbose($@"[Get-NetLocalGroupMember] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                            }
                            else
                            {
                                var Member = new LocalGroupMemberAPI
                                {
                                    ComputerName = Computer,
                                    GroupName = args.GroupName,
                                    MemberName = Info.lgrmi2_domainandname,
                                    SID = SidString,
                                    IsGroup = Info.lgrmi2_sidusage == SID_NAME_USE.SidTypeGroup
                                };
                                Members.Add(Member);
                            }
                        }

                        // free up the result buffer
                        NativeMethods.NetApiBufferFree(PtrInfo);

                        // try to extract out the machine SID by using the -500 account as a reference
                        var MachineSid = (Members.FirstOrDefault(x => (x as LocalGroupMemberAPI).SID.IsRegexMatch(".*-500") || (x as LocalGroupMemberAPI).SID.IsRegexMatch(".*-501")) as LocalGroupMemberAPI).SID;
                        if (MachineSid != null)
                        {
                            MachineSid = MachineSid.Substring(0, MachineSid.LastIndexOf('-'));

                            foreach (LocalGroupMemberAPI member in Members)
                            {
                                if (member.SID.IsRegexMatch(MachineSid))
                                {
                                    member.IsDomain = "false";
                                }
                                else
                                {
                                    member.IsDomain = "true";
                                }
                            }
                        }
                        else
                        {
                            foreach (LocalGroupMemberAPI member in Members)
                            {
                                if (!member.SID.IsRegexMatch("S-1-5-21"))
                                {
                                    member.IsDomain = "false";
                                }
                                else
                                {
                                    member.IsDomain = "UNKNOWN";
                                }
                            }
                        }
                        LocalGroupMembers.AddRange(Members);
                    }
                    else
                    {
                        Logger.Write_Verbose($@"[Get-NetLocalGroupMember] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                    }
                }
                else
                {
                    // otherwise we're using the WinNT service provider
                    try
                    {
                        var GroupProvider = new System.DirectoryServices.DirectoryEntry($@"WinNT://{Computer}/{args.GroupName},group");
                        IEnumerable Members = (IEnumerable)GroupProvider.Invoke("Members");
                        foreach (var obj in Members)
                        {
                            var LocalUser = new System.DirectoryServices.DirectoryEntry(obj);
                            var Member = new LocalGroupMemberWinNT
                            {
                                ComputerName = Computer,
                                GroupName = args.GroupName
                            };

                            var AdsPath = LocalUser.InvokeGet("AdsPath").ToString().Replace("WinNT://", "");
                            var IsGroup = LocalUser.SchemaClassName.IsLikeMatch("group");

                            bool MemberIsDomain;
                            string Name;
                            if (Regex.Matches(AdsPath, "/").Count == 1)
                            {
                                // DOMAIN\user
                                MemberIsDomain = true;
                                Name = AdsPath.Replace(@"/", @"\");
                            }
                            else
                            {
                                // DOMAIN\machine\user
                                MemberIsDomain = false;
                                Name = AdsPath.Substring(AdsPath.IndexOf('/') + 1).Replace(@"/", @"\");
                            }

                            Member.AccountName = Name;
                            Member.SID = new System.Security.Principal.SecurityIdentifier((byte[])LocalUser.InvokeGet("ObjectSID"), 0).Value;
                            Member.IsGroup = IsGroup;
                            Member.IsDomain = MemberIsDomain;

                            LocalGroupMembers.Add(Member);
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Get-NetLocalGroupMember] Error for {Computer} : {e}");
                    }
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return LocalGroupMembers;
        }

        private static string Convert_FileRight(uint FSR)
        {
            // From Ansgar Wiechers at http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
            var AccessMask = new Dictionary<UInt32, string> {
                { 0x80000000, "GenericRead" },
                { 0x40000000, "GenericWrite" },
                { 0x20000000, "GenericExecute" },
                { 0x10000000, "GenericAll" },
                { 0x02000000, "MaximumAllowed" },
                { 0x01000000, "AccessSystemSecurity" },
                { 0x00100000, "Synchronize" },
                { 0x00080000, "WriteOwner" },
                { 0x00040000, "WriteDAC" },
                { 0x00020000, "ReadControl" },
                { 0x00010000, "Delete" },
                { 0x00000100, "WriteAttributes" },
                { 0x00000080, "ReadAttributes" },
                { 0x00000040, "DeleteChild" },
                { 0x00000020, "Execute/Traverse" },
                { 0x00000010, "WriteExtendedAttributes" },
                { 0x00000008, "ReadExtendedAttributes" },
                { 0x00000004, "AppendData/AddSubdirectory" },
                { 0x00000002, "WriteData/AddFile" },
                { 0x00000001, "ReadData/ListDirectory" }
            };

            var SimplePermissions = new Dictionary<UInt32, string> {
                { 0x1f01ff, "FullControl" },
                { 0x0301bf, "Modify" },
                { 0x0200a9, "ReadAndExecute" },
                { 0x02019f, "ReadAndWrite" },
                { 0x020089, "Read" },
                { 0x000116, "Write" }
            };

            var Permissions = new List<string>();

            // get simple permission
            foreach (var key in SimplePermissions.Keys)
            {
                if ((FSR & key) == key)
                {
                    Permissions.Add(SimplePermissions[key]);
                    FSR = FSR & ~key;
                }
            }

            // get remaining extended permissions
            foreach (var key in AccessMask.Keys)
            {
                if ((FSR & key) != 0)
                    Permissions.Add(AccessMask[key]);
            }

            return string.Join(",", Permissions);
        }

    }
}
