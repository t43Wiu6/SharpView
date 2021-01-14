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
    class FindInterestingDomainShareFile
    {
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



                foreach (var Share in SearchShares)
                {

                    Logger.Write_Verbose($@"Searching share: {Share}");

                    var SearchArgs = new Args_Find_InterestingFile

                    {

                        Path = new[] { Share },

                        Include = Include

                    };

                    if (OfficeDocs)
                    {

                        SearchArgs.OfficeDocs = OfficeDocs;

                    }

                    if (FreshEXEs)
                    {

                        SearchArgs.FreshEXEs = FreshEXEs;

                    }

                    if (LastAccessTime != null)
                    {

                        SearchArgs.LastAccessTime = LastAccessTime;

                    }

                    if (LastWriteTime != null)
                    {

                        SearchArgs.LastWriteTime = LastWriteTime;

                    }

                    if (CreationTime != null)
                    {

                        SearchArgs.CreationTime = CreationTime;

                    }

                    if (CheckWriteAccess)
                    {

                        SearchArgs.CheckWriteAccess = CheckWriteAccess;

                    }

                    FoundFiles.AddRange(FindInterestingFile.Find_InterestingFile(SearchArgs));

                }

            }



            if (TokenHandle != IntPtr.Zero)

            {

                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);

            }

            return FoundFiles;

        }

        public static IEnumerable<FoundFile> Find_InterestingDomainShareFile(Args_Find_InterestingDomainShareFile args = null)
        {
            if (args == null) args = new Args_Find_InterestingDomainShareFile();

            var ComputerSearcherArguments = new Args_Get_DomainComputer
            {
                Properties = new[] { "dnshostname" },
                Domain = args.ComputerDomain,
                LDAPFilter = args.ComputerLDAPFilter,
                SearchBase = args.ComputerSearchBase,
                OperatingSystem = args.OperatingSystem,
                ServicePack = args.ServicePack,
                SiteName = args.SiteName,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            string[] TargetComputers;
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Querying computers in the domain");
                TargetComputers = GetDomainComputer.Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }

            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-InterestingDomainShareFile] No hosts found to enumerate");
            }
            Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] TargetComputers length: {TargetComputers.Length}");

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                if (args.Delay != 0 || args.StopOnSuccess)
                {
                    LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential
                    });
                }
                else
                {
                    LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential,
                        Quiet = true
                    });
                }
            }

            var rets = new List<FoundFile>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0 || args.StopOnSuccess)
            {
                Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Delay: {args.Delay}, Jitter: {args.Jitter}");

                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var ret = _Find_InterestingDomainShareFile(new[] { TargetComputer }, args.Include, args.ExcludedShares, args.OfficeDocs, /*args.ExcludeHidden*/false, args.FreshEXEs, /*args.CheckWriteAccess*/ false, args.LastAccessTime, args.LastWriteTime, args.CreationTime, LogonToken);
                    if (ret != null)
                        rets.AddRange(ret);
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                            TargetComputers,
                            TargetComputer =>
                            {
                                var ret = _Find_InterestingDomainShareFile(new[] { TargetComputer }, args.Include, args.ExcludedShares, args.OfficeDocs, /*args.ExcludeHidden*/false, args.FreshEXEs, /*args.CheckWriteAccess*/ false, args.LastAccessTime, args.LastWriteTime, args.CreationTime, LogonToken);
                                lock (rets)
                                {
                                    if (ret != null)
                                        rets.AddRange(ret);
                                }
                            });
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return rets;
        }

    }
}
