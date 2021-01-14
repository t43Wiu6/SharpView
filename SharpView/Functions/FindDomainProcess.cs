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
    class FindDomainProcess
    {
        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<UserProcess> _Find_DomainProcess(string[] ComputerName, string[] ProcessName, string[] TargetUsers, System.Net.NetworkCredential Credential)
        {
            List<UserProcess> DomainProcesses = new List<UserProcess>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up)
                {
                    // try to enumerate all active processes on the remote host
                    // and search for a specific process name
                    IEnumerable<UserProcess> Processes;
                    if (Credential != null)
                    {
                        Processes = GetWMIProcess.Get_WMIProcess(new Args_Get_WMIProcess { Credential = Credential, ComputerName = new[] { TargetComputer } });
                    }
                    else
                    {
                        Processes = GetWMIProcess.Get_WMIProcess(new Args_Get_WMIProcess { ComputerName = new[] { TargetComputer } });
                    }
                    foreach (var Process in Processes)
                    {
                        // if we're hunting for a process name or comma-separated names
                        if (ProcessName != null)
                        {
                            if (ProcessName.Contains(Process.ProcessName))
                            {
                                DomainProcesses.Add(Process);
                            }
                        }
                        // if the session user is in the target list, display some output
                        else if (TargetUsers.Contains(Process.User))
                        {
                            DomainProcesses.Add(Process);
                        }
                    }
                }
            }
            return DomainProcesses;
        }

        public static IEnumerable<UserProcess> Find_DomainProcess(Args_Find_DomainProcess args = null)
        {
            if (args == null) args = new Args_Find_DomainProcess();

            var ComputerSearcherArguments = new Args_Get_DomainComputer
            {
                Properties = new[] { "dnshostname" },
                Domain = args.Domain,
                LDAPFilter = args.ComputerLDAPFilter,
                SearchBase = args.ComputerSearchBase,
                Unconstrained = args.Unconstrained,
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
            if (!string.IsNullOrEmpty(args.ComputerDomain))
                ComputerSearcherArguments.Domain = args.ComputerDomain;

            var UserSearcherArguments = new Args_Get_DomainUser
            {
                Properties = new[] { "samaccountname" },
                Identity = args.UserIdentity,
                Domain = args.Domain,
                LDAPFilter = args.UserLDAPFilter,
                SearchBase = args.UserSearchBase,
                AdminCount = args.UserAdminCount,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            if (!string.IsNullOrEmpty(args.UserDomain))
                UserSearcherArguments.Domain = args.UserDomain;

            // first, build the set of computers to enumerate
            string[] TargetComputers = null;
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                Logger.Write_Verbose(@"[Find-DomainProcess] Querying computers in the domain");
                TargetComputers = GetDomainComputer.Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }
            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-DomainProcess] No hosts found to enumerate");
            }
            Logger.Write_Verbose($@"[Find-DomainProcess] TargetComputers length: {TargetComputers.Length}");

            // now build the user target set
            List<string> TargetProcessName = null;
            string[] TargetUsers = null;
            if (args.ProcessName != null)
            {
                TargetProcessName = new List<string>();
                foreach (var T in args.ProcessName)
                {
                    TargetProcessName.AddRange(T.Split(','));
                }
            }
            else if (args.UserIdentity != null || args.UserLDAPFilter != null || args.UserSearchBase != null || args.UserAdminCount/* || args.UserAllowDelegation*/)
            {
                TargetUsers = GetDomainUser.Get_DomainUser(UserSearcherArguments).Select(x => (x as LDAPProperty).samaccountname).ToArray();
            }
            else
            {
                var GroupSearcherArguments = new Args_Get_DomainGroupMember
                {
                    Identity = args.UserGroupIdentity,
                    Recurse = true,
                    Domain = args.UserDomain,
                    SearchBase = args.UserSearchBase,
                    Server = args.Server,
                    SearchScope = args.SearchScope,
                    ResultPageSize = args.ResultPageSize,
                    ServerTimeLimit = args.ServerTimeLimit,
                    Tombstone = args.Tombstone,
                    Credential = args.Credential
                };
                TargetUsers = GetDomainGroupMember.Get_DomainGroupMember(GroupSearcherArguments).Select(x => x.MemberName).ToArray();
            }

            var rets = new List<UserProcess>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0 || args.StopOnSuccess)
            {
                Logger.Write_Verbose($@"[Find-DomainProcess] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-DomainProcess] Delay: {args.Delay}, Jitter: {args.Jitter}");
                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-DomainProcess] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var Result = _Find_DomainProcess(new[] { TargetComputer }, TargetProcessName?.ToArray(), TargetUsers, args.Credential);
                    if (Result != null)
                        rets.AddRange(Result);

                    if (Result != null && args.StopOnSuccess)
                    {
                        Logger.Write_Verbose("[Find-DomainProcess] Target user found, returning early");
                        return rets;
                    }
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainProcess] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                                    TargetComputers,
                                    TargetComputer =>
                                    {
                                        var Result = _Find_DomainProcess(new[] { TargetComputer }, TargetProcessName?.ToArray(), TargetUsers, args.Credential);
                                        lock (rets)
                                        {
                                            if (Result != null)
                                                rets.AddRange(Result);
                                        }
                                    });
            }

            return rets;
        }

        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<UserLocation> _Find_DomainUserLocation(string[] ComputerName, string[] TargetUsers, string CurrentUser, bool Stealth, bool CheckAccess, IntPtr TokenHandle)
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

            var UserLocations = new List<UserLocation>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up)
                {
                    var Sessions = GetNetSession.Get_NetSession(new Args_Get_NetSession { ComputerName = new[] { TargetComputer } });
                    foreach (var Session in Sessions)
                    {
                        var UserName = Session.UserName;
                        var CName = Session.CName;

                        if (!CName.IsNullOrEmpty() && CName.StartsWith(@"\\"))
                        {
                            CName = CName.TrimStart('\\');
                        }

                        // make sure we have a result, and ignore computer$ sessions
                        if ((UserName != null) && (UserName.Trim() != "") && (!UserName.IsRegexMatch(CurrentUser)) && (!UserName.IsRegexMatch(@"\$$")))
                        {
                            if ((TargetUsers == null) || (TargetUsers.Contains(UserName)))
                            {
                                var UserLocation = new UserLocation
                                {
                                    UserDomain = null,
                                    UserName = UserName,
                                    ComputerName = TargetComputer,
                                    SessionFrom = CName
                                };

                                // try to resolve the DNS hostname of $Cname
                                try
                                {
                                    var CNameDNSName = System.Net.Dns.GetHostEntry(CName).HostName;
                                    UserLocation.SessionFromName = CNameDNSName;
                                }
                                catch
                                {
                                    UserLocation.SessionFromName = null;
                                }

                                // see if we're checking to see if we have local admin access on this machine
                                if (CheckAccess)
                                {
                                    var Admin = TestAdminAccess.Test_AdminAccess(new Args_Test_AdminAccess { ComputerName = new[] { CName } }).FirstOrDefault();
                                    UserLocation.LocalAdmin = Admin != null ? Admin.IsAdmin : false;
                                }
                                else
                                {
                                    UserLocation.LocalAdmin = false;
                                }
                                UserLocations.Add(UserLocation);
                            }
                        }
                    }
                    if (!Stealth)
                    {
                        // if we're not 'stealthy', enumerate loggedon users as well
                        var LoggedOn = GetNetLoggedon.Get_NetLoggedon(new Args_Get_NetLoggedon { ComputerName = new[] { TargetComputer } });
                        foreach (var User in LoggedOn)
                        {
                            var UserName = User.UserName;
                            var UserDomain = User.LogonDomain;

                            // make sure wet have a result
                            if ((UserName != null) && (UserName.Trim() != ""))
                            {
                                if ((TargetUsers == null) || (TargetUsers.Contains(UserName)) && (!UserName.IsRegexMatch(@"\$$")))
                                {
                                    var IPAddress = ResolveIPAddress.Resolve_IPAddress(new Args_Resolve_IPAddress { ComputerName = new[] { TargetComputer } }).FirstOrDefault()?.IPAddress;
                                    var UserLocation = new UserLocation
                                    {
                                        UserDomain = UserDomain,
                                        UserName = UserName,
                                        ComputerName = TargetComputer,
                                        IPAddress = IPAddress,
                                        SessionFrom = null,
                                        SessionFromName = null
                                    };

                                    // see if we're checking to see if we have local admin access on this machine
                                    if (CheckAccess)
                                    {
                                        var Admin = TestAdminAccess.Test_AdminAccess(new Args_Test_AdminAccess { ComputerName = new[] { TargetComputer } }).FirstOrDefault();
                                        UserLocation.LocalAdmin = Admin.IsAdmin;
                                    }
                                    else
                                    {
                                        UserLocation.LocalAdmin = false;
                                    }
                                    UserLocations.Add(UserLocation);
                                }
                            }
                        }
                    }
                }
            }

            if (TokenHandle != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return UserLocations;
        }

    }
}
