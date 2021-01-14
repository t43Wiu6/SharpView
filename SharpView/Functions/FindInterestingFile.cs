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
    class FindInterestingFile
    {
        private static bool Test_Write(string Path)

        {

            // short helper to check is the current user can write to a file

            try
            {

                var Filetest = File.OpenWrite(Path);

                Filetest.Close();

                return true;

            }

            catch
            {

                return false;

            }

        }
        public static IEnumerable<FoundFile> Find_InterestingFile(Args_Find_InterestingFile args = null)
        {
            if (args == null) args = new Args_Find_InterestingFile();

            if (args.OfficeDocs)
            {
                args.Include = new[] { ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx" };
            }
            else if (args.FreshEXEs)
            {
                // find .exe's accessed within the last 7 days
                args.LastAccessTime = DateTime.Now.Date.AddDays(-7);
                args.Include = new[] { ".exe" };
            }

            var FoundFiles = new List<FoundFile>();
            var MappedComputers = new Dictionary<string, bool>();
            foreach (var TargetPath in args.Path)
            {
                if ((TargetPath.IsRegexMatch(@"\\\\.*\\.*")) && (args.Credential != null))
                {

                    var HostComputer = new System.Uri(TargetPath).Host;
                    if (!MappedComputers[HostComputer])
                    {
                        // map IPC$ to this computer if it's not already
                        AddRemoteConnection.Add_RemoteConnection(new Args_Add_RemoteConnection { ComputerName = new[] { HostComputer }, Credential = args.Credential });
                        MappedComputers[HostComputer] = true;
                    }
                }

                var files = PathExtension.GetDirectoryFiles(TargetPath, args.Include, SearchOption.AllDirectories);
                //var files = Directory.EnumerateFiles(TargetPath, "*.*", SearchOption.AllDirectories)
                //                                   .Where(x => args.Include.EndsWith(x, StringComparison.OrdinalIgnoreCase));

                foreach (var file in files)
                {
                    var Continue = true;
                    // check if we're excluding hidden files
                    if (args.ExcludeHidden)
                    {
                        Continue = !File.GetAttributes(file).HasFlag(FileAttributes.Hidden);
                    }
                    // check if we're excluding folders
                    if (args.ExcludeFolders && Directory.Exists(file))
                    {
                        Logger.Write_Verbose($@"Excluding: {file}");
                        Continue = false;
                    }
                    if (args.LastAccessTime != null && (File.GetLastAccessTime(file) < args.LastAccessTime.Value))
                    {
                        Continue = false;
                    }
                    if (args.LastWriteTime != null && (File.GetLastWriteTime(file) < args.LastWriteTime.Value))
                    {
                        Continue = false;
                    }
                    if (args.CreationTime != null && (File.GetCreationTime(file) < args.CreationTime.Value))
                    {
                        Continue = false;
                    }
                    if (args.CheckWriteAccess && !Test_Write(file))
                    {
                        Continue = false;
                    }
                    if (Continue)
                    {

                        String owner;
                        try
                        {
                             owner = File.GetAccessControl(file).GetOwner(typeof(SecurityIdentifier)).Translate(typeof(System.Security.Principal.NTAccount)).Value;
                        }
                        catch{
                             owner = "Access was Denied"; 
                        }

                        DateTime lastAccessTime;
                        try
                        {
                            lastAccessTime = File.GetLastAccessTime(file);
                        }
                        catch { lastAccessTime = new DateTime(); }

                        DateTime lastWriteTime;
                        try
                        {
                            lastWriteTime = File.GetLastWriteTime(file);
                        } catch { lastWriteTime = new DateTime(); }

                        DateTime creationTime;
                        try
                        {
                            creationTime = File.GetCreationTime(file);
                        } catch { creationTime = new DateTime(); }

                        long length;
                        try
                        {
                            length =new FileInfo(file).Length; 
                        }catch { length = 0; }
                      

                        var FoundFile = new FoundFile
                        {
                            Path = file,
                            Owner = owner,
                            LastAccessTime = lastAccessTime,
                            LastWriteTime = lastWriteTime,
                            CreationTime = creationTime,
                            Length = length
                        };
                        FoundFiles.Add(FoundFile);
                    }
                }
            }

            // remove the IPC$ mappings
            foreach (var key in MappedComputers.Keys)
            {
                RemoveRemoteConnection.Remove_RemoteConnection(new Args_Remove_RemoteConnection { ComputerName = new[] { key } });
            }
            return FoundFiles;
        }

        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<FoundFile> _Find_InterestingDomainShareFile(string[] ComputerName, string[] Include, string[] ExcludedShares, bool OfficeDocs, bool ExcludeHidden, bool FreshEXEs, bool CheckWriteAccess, DateTime? LastAccessTime, DateTime? LastWriteTime, DateTime? CreationTime, IntPtr TokenHandle)
        {
            var LogonToken = IntPtr.Zero;
            if (TokenHandle != IntPtr.Zero)
            {
                // impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    TokenHandle = TokenHandle,
                    Quiet = true
                });
            }

            var FoundFiles = new List<FoundFile>();
            foreach (var TargetComputer in ComputerName)
            {
                var SearchShares = new List<string>();
                if (TargetComputer.StartsWith(@"\\"))
                {
                    // if a share is passed as the server
                    SearchShares.Add(TargetComputer);
                }
                else
                {
                    var Up = TestConnection.Ping(TargetComputer, 1);
                    if (Up)
                    {
                        // get the shares for this host and check what we find
                        var Shares = GetNetShare.Get_NetShare(new Args_Get_NetShare
                        {
                            ComputerName = new[] { TargetComputer }
                        });

                        foreach (var Share in Shares)
                        {
                            var ShareName = Share.Name;
                            var Path = @"\\" + TargetComputer + @"\" + ShareName;

                            // make sure we get a real share name back
                            if ((!string.IsNullOrEmpty(ShareName)) && (ShareName.Trim() != ""))
                            {
                                // skip this share if it's in the exclude list
                                if (!ExcludedShares.ContainsNoCase(ShareName))
                                {
                                    // check if the user has access to this path
                                    try
                                    {
                                        Directory.GetFiles(Path);
                                        SearchShares.Add(Path);
                                    }
                                    catch
                                    {
                                        Logger.Write_Verbose($@"[!] No access to {Path}");
                                    }
                                }
                            }
                        }
                    }
                }

                foreach (var Share in SearchShares) {
                    Logger.Write_Verbose($@"Searching share: {Share}");
                    var SearchArgs = new Args_Find_InterestingFile
                    {
                        Path = new[] { Share },
                        Include = Include
                    };
                    if (OfficeDocs) {
                        SearchArgs.OfficeDocs = OfficeDocs;
                    }
                    if (FreshEXEs) {
                        SearchArgs.FreshEXEs = FreshEXEs;
                    }
                    if (LastAccessTime != null) {
                        SearchArgs.LastAccessTime = LastAccessTime;
                    }
                    if (LastWriteTime != null) {
                        SearchArgs.LastWriteTime = LastWriteTime;
                    }
                    if (CreationTime != null) {
                        SearchArgs.CreationTime = CreationTime;
                    }
                    if (CheckWriteAccess) {
                        SearchArgs.CheckWriteAccess = CheckWriteAccess;
                    }
                    FoundFiles.AddRange(Find_InterestingFile(SearchArgs));
                }
            }

            if (TokenHandle != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return FoundFiles;
        }

    }
}
