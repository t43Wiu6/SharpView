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
    class FindDomainLocalGroupMember
    { 
        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<object> _Find_DomainLocalGroupMember(string[] ComputerName, string GroupName, MethodType Method, IntPtr TokenHandle)
        {
            // Add check if user defaults to/selects "Administrators"
            if (GroupName == "Administrators") {
                var AdminSecurityIdentifier = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                GroupName = AdminSecurityIdentifier.Translate(typeof(System.Security.Principal.NTAccount)).Value.Split('\\').LastOrDefault();
            }
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
            var Members = new List<object>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up)
                {
                    var NetLocalGroupMemberArguments = new Args_Get_NetLocalGroupMember
                    {
                        ComputerName = new[] { TargetComputer },
                        Method = Method,
                        GroupName = GroupName
                    };
                    var ret = GetNetLocalGroupMember.Get_NetLocalGroupMember(NetLocalGroupMemberArguments);
                    if (ret != null)
                        Members.AddRange(ret);
                }
            }

            if (TokenHandle != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);

            }

            return Members;

        }
        public static IEnumerable<object> Find_DomainLocalGroupMember(Args_Find_DomainLocalGroupMember args = null)
        {
            if (args == null) args = new Args_Find_DomainLocalGroupMember();

            var ComputerSearcherArguments = new Args_Get_DomainComputer
            {
                Properties = new[] { "dnshostname" },
                Domain = args.ComputerDomain,
                LDAPFilter = args.ComputerLDAPFilter,
                SearchBase = args.ComputerSearchBase,
                //Unconstrained = args.Unconstrained,
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
                Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Querying computers in the domain");
                TargetComputers = GetDomainComputer.Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }

            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-DomainLocalGroupMember] No hosts found to enumerate");
            }
            Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] TargetComputers length: {TargetComputers.Length}");

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                if (args.Delay != 0/* || args.StopOnSuccess*/)
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

            var rets = new List<object>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0/* || args.StopOnSuccess*/)
            {
                Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Delay: {args.Delay}, Jitter: {args.Jitter}");
                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var ret = _Find_DomainLocalGroupMember(new[] { TargetComputer }, args.GroupName, args.Method, LogonToken);
                    if (ret != null)
                        rets.AddRange(ret);
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                        TargetComputers,
                        TargetComputer =>
                        {
                            var ret = _Find_DomainLocalGroupMember(new[] { TargetComputer }, args.GroupName, args.Method, LogonToken);
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

        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<ShareInfo> _Find_DomainShare(string[] ComputerName, bool CheckShareAccess, IntPtr TokenHandle)
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

            var DomainShares = new List<ShareInfo>();
            foreach (var TargetComputer in ComputerName)
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
                        // $Remark = $Share.Remark
                        var Path = @"\\" + TargetComputer + @"\" + ShareName;

                        if ((!string.IsNullOrEmpty(ShareName)) && (ShareName.Trim() != ""))
                        {
                            // see if we want to check access to this share
                            if (CheckShareAccess)
                            {
                                // check if the user has access to this path
                                try
                                {
                                    Directory.GetFiles(Path);
                                    DomainShares.Add(Share);
                                }
                                catch (Exception e)
                                {
                                    Logger.Write_Verbose($@"Error accessing share path {Path} : {e}");
                                }
                            }
                            else
                            {
                                DomainShares.Add(Share);
                            }
                        }
                    }
                }
            }

            if (TokenHandle != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return DomainShares;
        }

    }
}
