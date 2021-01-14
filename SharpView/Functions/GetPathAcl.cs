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
    class GetPathAcl
    {
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

        public static IEnumerable<FileACL> Get_PathAcl(Args_Get_PathAcl args = null)
        {
            if (args == null) args = new Args_Get_PathAcl();

            var ConvertArguments = new Args_ConvertFrom_SID
            {
                Credential = args.Credential
            };
            var MappedComputers = new Dictionary<string, bool>();

            var FileACLs = new List<FileACL>();
            foreach (var TargetPath in args.Path)
            {
                try
                {
                    if (TargetPath.IsRegexMatch(@"\\\\.*\\.*") && args.Credential != null)
                    {
                        var HostComputer = new System.Uri(TargetPath).Host;
                        if (!MappedComputers[HostComputer])
                        {
                            // map IPC$ to this computer if it's not already
                            AddRemoteConnection.Add_RemoteConnection(new Args_Add_RemoteConnection { ComputerName = new string[] { HostComputer }, Credential = args.Credential });
                            MappedComputers[HostComputer] = true;
                        }
                    }

                    FileSystemSecurity ACL;
                    var attr = File.GetAttributes(TargetPath);
                    if (attr.HasFlag(FileAttributes.Directory))
                        ACL = Directory.GetAccessControl(TargetPath);
                    else
                        ACL = File.GetAccessControl(TargetPath);

                    var arc = ACL.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                    foreach (FileSystemAccessRule ar in arc)
                    {
                        var SID = ar.IdentityReference.Value;
                        ConvertArguments.ObjectSID = new string[] { SID };
                        var Name = ConvertFromSID.ConvertFrom_SID(ConvertArguments);

                        var Out = new FileACL
                        {
                            Path = TargetPath,
                            FileSystemRights = Convert_FileRight((uint)ar.FileSystemRights),
                            IdentityReference = Name,
                            IdentitySID = SID,
                            AccessControlType = ar.AccessControlType
                        };
                        FileACLs.Add(Out);
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-PathAcl] error: {e}");
                }
            }

            // remove the IPC$ mappings
            RemoveRemoteConnection.Remove_RemoteConnection(new Args_Remove_RemoteConnection { ComputerName = MappedComputers.Keys.ToArray() });
            return FileACLs;
        }

    }
}
