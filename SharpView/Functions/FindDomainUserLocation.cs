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
    class FindDomainUserLocation
    {

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

        public static IEnumerable<UserLocation> Find_DomainUserLocation(Args_Find_DomainUserLocation args = null)
        {
            if (args == null) args = new Args_Find_DomainUserLocation();

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
                AllowDelegation = args.AllowDelegation,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            if (!string.IsNullOrEmpty(args.UserDomain))
                UserSearcherArguments.Domain = args.UserDomain;

            string[] TargetComputers = null;

            // first, build the set of computers to enumerate
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                if (args.Stealth)
                {
                    Logger.Write_Verbose($@"[Find-DomainUserLocation] Stealth enumeration using source: {args.StealthSource}");
                    var TargetComputerArrayList = new System.Collections.ArrayList();

                    if (args.StealthSource.ToString().IsRegexMatch("File|All"))
                    {
                        Logger.Write_Verbose("[Find-DomainUserLocation] Querying for file servers");
                        var FileServerSearcherArguments = new Args_Get_DomainFileServer
                        {
                            Domain = new[] { args.Domain },
                            SearchBase = args.ComputerSearchBase,
                            Server = args.Server,
                            SearchScope = args.SearchScope,
                            ResultPageSize = args.ResultPageSize,
                            ServerTimeLimit = args.ServerTimeLimit,
                            Tombstone = args.Tombstone,
                            Credential = args.Credential
                        };
                        if (!string.IsNullOrEmpty(args.ComputerDomain))
                            FileServerSearcherArguments.Domain = new[] { args.ComputerDomain };
                        var FileServers = GetDomainFileServer.Get_DomainFileServer(FileServerSearcherArguments);
                        TargetComputerArrayList.AddRange(FileServers);
                    }
                    if (args.StealthSource.ToString().IsRegexMatch("DFS|All"))
                    {
                        Logger.Write_Verbose(@"[Find-DomainUserLocation] Querying for DFS servers");
                        // { TODO: fix the passed parameters to Get-DomainDFSShare
                        // $ComputerName += Get-DomainDFSShare -Domain $Domain -Server $DomainController | ForEach-Object {$_.RemoteServerName}
                    }
                    if (args.StealthSource.ToString().IsRegexMatch("DC|All"))
                    {
                        Logger.Write_Verbose(@"[Find-DomainUserLocation] Querying for domain controllers");
                        var DCSearcherArguments = new Args_Get_DomainController
                        {
                            LDAP = true,
                            Domain = args.Domain,
                            Server = args.Server,
                            Credential = args.Credential
                        };
                        if (!string.IsNullOrEmpty(args.ComputerDomain))
                            DCSearcherArguments.Domain = args.ComputerDomain;
                        var DomainControllers = GetDomainController.Get_DomainController(DCSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
                        TargetComputerArrayList.AddRange(DomainControllers);
                    }
                    TargetComputers = TargetComputerArrayList.ToArray() as string[];
                }
            }
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                if (args.Stealth)
                {
                    Logger.Write_Verbose($@"[Find-DomainUserLocation] Stealth enumeration using source: {args.StealthSource}");
                    var TargetComputerArrayList = new System.Collections.ArrayList();

                    if (args.StealthSource.ToString().IsRegexMatch("File|All"))
                    {
                        Logger.Write_Verbose("[Find-DomainUserLocation] Querying for file servers");
                        var FileServerSearcherArguments = new Args_Get_DomainFileServer
                        {
                            Domain = new[] { args.Domain },
                            SearchBase = args.ComputerSearchBase,
                            Server = args.Server,
                            SearchScope = args.SearchScope,
                            ResultPageSize = args.ResultPageSize,
                            ServerTimeLimit = args.ServerTimeLimit,
                            Tombstone = args.Tombstone,
                            Credential = args.Credential
                        };
                        if (!string.IsNullOrEmpty(args.ComputerDomain))
                            FileServerSearcherArguments.Domain = new[] { args.ComputerDomain };
                        var FileServers = GetDomainFileServer.Get_DomainFileServer(FileServerSearcherArguments);
                        TargetComputerArrayList.AddRange(FileServers);
                    }
                    if (args.StealthSource.ToString().IsRegexMatch("DFS|All"))
                    {
                        Logger.Write_Verbose(@"[Find-DomainUserLocation] Querying for DFS servers");
                        // { TODO: fix the passed parameters to Get-DomainDFSShare
                        // $ComputerName += Get-DomainDFSShare -Domain $Domain -Server $DomainController | ForEach-Object {$_.RemoteServerName}
                    }
                    if (args.StealthSource.ToString().IsRegexMatch("DC|All"))
                    {
                        Logger.Write_Verbose(@"[Find-DomainUserLocation] Querying for domain controllers");
                        var DCSearcherArguments = new Args_Get_DomainController
                        {
                            LDAP = true,
                            Domain = args.Domain,
                            Server = args.Server,
                            Credential = args.Credential
                        };
                        if (!string.IsNullOrEmpty(args.ComputerDomain))
                            DCSearcherArguments.Domain = args.ComputerDomain;
                        var DomainControllers = GetDomainController.Get_DomainController(DCSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
                        TargetComputerArrayList.AddRange(DomainControllers);
                    }
                    TargetComputers = TargetComputerArrayList.ToArray() as string[];
                }
                else
                {
                    Logger.Write_Verbose("[Find-DomainUserLocation] Querying for all computers in the domain");
                    TargetComputers = GetDomainComputer.Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
                }
            }
            Logger.Write_Verbose($@"[Find-DomainUserLocation] TargetComputers length: {TargetComputers.Length}");
            if (TargetComputers.Length == 0)
            {
                throw new Exception("[Find-DomainUserLocation] No hosts found to enumerate");
            }

            // get the current user so we can ignore it in the results
            string CurrentUser;
            if (args.Credential != null)
            {
                CurrentUser = args.Credential.UserName;
            }
            else
            {
                CurrentUser = Environment.UserName.ToLower();
            }

            // now build the user target set
            string[] TargetUsers = null;
            if (args.ShowAll)
            {
                TargetUsers = new string[] { };
            }
            else if (args.UserIdentity != null || args.UserLDAPFilter != null || args.UserSearchBase != null || args.UserAdminCount || args.UserAllowDelegation)
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

            Logger.Write_Verbose($@"[Find-DomainUserLocation] TargetUsers length: {TargetUsers.Length}");
            if ((!args.ShowAll) && (TargetUsers.Length == 0))
            {
                throw new Exception("[Find-DomainUserLocation] No users found to target");
            }

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

            var rets = new List<UserLocation>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0/* || args.StopOnSuccess*/)
            {
                Logger.Write_Verbose($@"[Find-DomainUserLocation] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-DomainUserLocation] Delay: {args.Delay}, Jitter: {args.Jitter}");

                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-DomainUserLocation] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var Result = _Find_DomainUserLocation(new[] { TargetComputer }, TargetUsers, CurrentUser, args.Stealth, args.CheckAccess, LogonToken);
                    if (Result != null)
                        rets.AddRange(Result);
                    if (Result != null && args.StopOnSuccess)
                    {
                        Logger.Write_Verbose("[Find-DomainUserLocation] Target user found, returning early");
                        return rets;
                    }
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainUserLocation] Using threading with threads: {args.Threads}");
                Logger.Write_Verbose($@"[Find-DomainUserLocation] TargetComputers length: {TargetComputers.Length}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                            TargetComputers,
                            TargetComputer =>
                            {
                                var Result = _Find_DomainUserLocation(new[] { TargetComputer }, TargetUsers, CurrentUser, args.Stealth, args.CheckAccess, LogonToken);
                                lock (rets)
                                {
                                    if (Result != null)
                                        rets.AddRange(Result);
                                }
                            });
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return rets;
        }

        private static bool Test_Write(string Path)
        {
            // short helper to check is the current user can write to a file
            try {
                var Filetest = File.OpenWrite(Path);
                Filetest.Close();
                return true;
            }
            catch {
                return false;
            }
        }

    }
}
