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
    class FindDomainUserEvent
    {
        private static IEnumerable<IWinEvent> _Find_DomainUserEvent(string[] ComputerName, DateTime StartTime, DateTime EndTime, int MaxEvents, string[] TargetUsers, Dictionary<string, string> Filter, System.Net.NetworkCredential Credential)

        {

            var Events = new List<IWinEvent>();

            foreach (var TargetComputer in ComputerName)

            {

                var Up = TestConnection.Ping(TargetComputer, 1);

                if (Up)

                {

                    var DomainUserEventArgs = new Args_Get_DomainUserEvent

                    {

                        ComputerName = new[] { TargetComputer },

                        StartTime = StartTime,

                        EndTime = EndTime,

                        MaxEvents = MaxEvents,

                        Credential = Credential

                    };

                    if (Filter != null || TargetUsers != null)

                    {

                        if (TargetUsers != null)

                        {

                            GetDomainUserEvent.Get_DomainUserEvent(DomainUserEventArgs).Where(x => TargetUsers.Contains((x is LogonEvent) ? (x as LogonEvent).TargetUserName : (x as ExplicitCredentialLogonEvent).TargetUserName));

                        }

                        else

                        {

                            var Operator = "or";

                            foreach (var key in Filter.Keys)

                            {

                                if ((key == "Op") || (key == "Operator") || (key == "Operation"))

                                {

                                    if ((Filter[key].IsRegexMatch("&")) || (Filter[key] == "and"))

                                    {

                                        Operator = "and";

                                    }

                                }

                            }

                            var Keys = Filter.Keys.Where(x => (x != "Op") && (x != "Operator") && (x != "Operation"));

                            var events = GetDomainUserEvent.Get_DomainUserEvent(DomainUserEventArgs);

                            foreach (var evt in events)

                            {

                                if (Operator == "or")

                                {

                                    foreach (var Key in Keys)

                                    {

                                        if (evt.GetPropValue<string>(Key).IsRegexMatch(Filter[Key]))

                                        {

                                            Events.Add(evt);

                                        }

                                    }

                                }

                                else

                                {

                                    // and all clauses

                                    foreach (var Key in Keys)

                                    {

                                        if (!evt.GetPropValue<string>(Key).IsRegexMatch(Filter[Key]))

                                        {

                                            break;

                                        }

                                        Events.Add(evt);

                                    }

                                }

                            }

                        }

                    }

                    else

                    {

                        GetDomainUserEvent.Get_DomainUserEvent(DomainUserEventArgs);

                    }

                }

            }



            return Events;

        }

        public static IEnumerable<object> Find_DomainUserEvent(Args_Find_DomainUserEvent args = null)
        {
            if (args == null) args = new Args_Find_DomainUserEvent();

            var UserSearcherArguments = new Args_Get_DomainUser
            {
                Properties = new[] { "samaccountname" },
                Identity = args.UserIdentity,
                Domain = args.UserDomain,
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

            string[] TargetUsers = null;
            if (args.UserIdentity != null || !string.IsNullOrEmpty(args.UserLDAPFilter) || !string.IsNullOrEmpty(args.UserSearchBase) || args.UserAdminCount)
            {
                TargetUsers = GetDomainUser.Get_DomainUser(UserSearcherArguments).Select(x => (x as LDAPProperty).samaccountname).ToArray();
            }
            else if (args.UserGroupIdentity != null || (args.Filter == null))
            {
                // otherwise we're querying a specific group
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
                Logger.Write_Verbose($@"UserGroupIdentity: {args.UserGroupIdentity.ToJoinedString()}");
                TargetUsers = GetDomainGroupMember.Get_DomainGroupMember(GroupSearcherArguments).Select(x => x.MemberName).ToArray();
            }

            // build the set of computers to enumerate
            string[] TargetComputers = null;
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                // if not -ComputerName is passed, query the current (or target) domain for domain controllers
                var DCSearcherArguments = new Args_Get_DomainController
                {
                    LDAP = true,
                    Domain = args.Domain,
                    Server = args.Server,
                    Credential = args.Credential
                };
                Logger.Write_Verbose($@"[Find-DomainUserEvent] Querying for domain controllers in domain: {args.Domain}");
                TargetComputers = GetDomainController.Get_DomainController(DCSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }
            Logger.Write_Verbose($@"[Find-DomainUserEvent] TargetComputers length: {TargetComputers.Count()}");
            Logger.Write_Verbose($@"[Find-DomainUserEvent] TargetComputers {TargetComputers.ToJoinedString()}");
            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-DomainUserEvent] No hosts found to enumerate");
            }

            var rets = new List<IWinEvent>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0 || args.StopOnSuccess)
            {
                Logger.Write_Verbose($@"[Find-DomainUserEvent] TargetComputers length: {TargetComputers.Length}");
                Logger.Write_Verbose($@"[Find-DomainUserEvent] Delay: {args.Delay}, Jitter: {args.Jitter}");
                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-DomainUserEvent] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var Result = _Find_DomainUserEvent(new[] { TargetComputer }, args.StartTime, args.EndTime, args.MaxEvents, TargetUsers, args.Filter, args.Credential);
                    if (Result != null)
                        rets.AddRange(Result);

                    if (Result != null && args.StopOnSuccess)
                    {
                        Logger.Write_Verbose("[Find-DomainUserEvent] Target user found, returning early");
                        return rets;
                    }
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainUserEvent] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                                TargetComputers,
                                TargetComputer =>
                                {
                                    var Result = _Find_DomainUserEvent(new[] { TargetComputer }, args.StartTime, args.EndTime, args.MaxEvents, TargetUsers, args.Filter, args.Credential);
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

    }
}
