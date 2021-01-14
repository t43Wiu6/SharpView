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
    class GetDomainUserEvent
    { 
        public static IEnumerable<IWinEvent> Get_DomainUserEvent(Args_Get_DomainUserEvent args = null)
        {
            if (args == null) args = new Args_Get_DomainUserEvent();

            // the XML filter we're passing to Get-WinEvent
            var XPathFilter = $@"
<QueryList>
    <Query Id=""0"" Path=""Security"">

        <!--Logon events-->
        <Select Path = ""Security"">
             *[
                 System[
                     Provider[
                         @Name='Microsoft-Windows-Security-Auditing'
                     ] 
                     and (Level=4 or Level=0) and (EventID=4624) 
                     and TimeCreated[
                         @SystemTime&gt;='{args.StartTime.ToUniversalTime().ToString("s")}' and @SystemTime&lt;='{args.EndTime.ToUniversalTime().ToString("s")}'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path=""Security"">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='{args.StartTime.ToUniversalTime().ToString("s")}' and @SystemTime&lt;='{args.EndTime.ToUniversalTime().ToString("s")}'
                    ]
                ]
            ]
        </Select>

        <Suppress Path=""Security"">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
";

            var Events = new List<IWinEvent>();
            foreach (var Computer in args.ComputerName)
            {
                EventLogQuery query = new EventLogQuery(@"Security", PathType.LogName, XPathFilter);
                EventLogReader reader = new EventLogReader(query);
                for (EventRecord Event = reader.ReadEvent(); null != Event; Event = reader.ReadEvent())
                {
                    if (args.ComputerName.Any(x => Event.MachineName.Equals(x, StringComparison.OrdinalIgnoreCase) || Event.MachineName.StartsWith(x, StringComparison.OrdinalIgnoreCase)))
                    {
                        var Properties = Event.Properties;
                        switch (Event.Id)
                        {
                            case 4624: // logon event
                                // skip computer logons, for now...
                                if (!Event.Properties[5].Value.ToString().EndsWith(@"$"))
                                {
                                    Events.Add(new LogonEvent
                                    {
                                        ComputerName = Computer,
                                        TimeCreated = Event.TimeCreated,
                                        EventId = Event.Id,
                                        SubjectUserSid = Properties[0].Value.ToString(),
                                        SubjectUserName = Properties[1].Value.ToString(),
                                        SubjectDomainName = Properties[2].Value.ToString(),
                                        SubjectLogonId = Properties[3].Value.ToString(),
                                        TargetUserSid = Properties[4].Value.ToString(),
                                        TargetUserName = Properties[5].Value.ToString(),
                                        TargetDomainName = Properties[6].Value.ToString(),
                                        TargetLogonId = Properties[7].Value.ToString(),
                                        LogonType = Properties[8].Value.ToString(),
                                        LogonProcessName = Properties[9].Value.ToString(),
                                        AuthenticationPackageName = Properties[10].Value.ToString(),
                                        WorkstationName = Properties[11].Value.ToString(),
                                        LogonGuid = Properties[12].Value.ToString(),
                                        TransmittedServices = Properties[13].Value.ToString(),
                                        LmPackageName = Properties[14].Value.ToString(),
                                        KeyLength = Properties[15].Value.ToString(),
                                        ProcessId = Properties[16].Value.ToString(),
                                        ProcessName = Properties[17].Value.ToString(),
                                        IpAddress = Properties[18].Value.ToString(),
                                        IpPort = Properties[19].Value.ToString(),
                                        ImpersonationLevel = Properties[20].Value.ToString(),
                                        RestrictedAdminMode = Properties[21].Value.ToString(),
                                        TargetOutboundUserName = Properties[22].Value.ToString(),
                                        TargetOutboundDomainName = Properties[23].Value.ToString(),
                                        VirtualAccount = Properties[24].Value.ToString(),
                                        TargetLinkedLogonId = Properties[25].Value.ToString(),
                                        ElevatedToken = Properties[26].Value.ToString()
                                    });
                                }
                                break;
                            case 4648: // logon with explicit credential
                                // skip computer logons, for now...
                                if (!Properties[5].Value.ToString().EndsWith(@"$") && Properties[11].Value.ToString().IsRegexMatch(@"taskhost\.exe"))
                                {
                                    Events.Add(new ExplicitCredentialLogonEvent
                                    {
                                        ComputerName = Computer,
                                        TimeCreated = Event.TimeCreated,
                                        EventId = Event.Id,
                                        SubjectUserSid = Properties[0].Value.ToString(),
                                        SubjectUserName = Properties[1].Value.ToString(),
                                        SubjectDomainName = Properties[2].Value.ToString(),
                                        SubjectLogonId = Properties[3].Value.ToString(),
                                        LogonGuid = Properties[4].Value.ToString(),
                                        TargetUserName = Properties[5].Value.ToString(),
                                        TargetDomainName = Properties[6].Value.ToString(),
                                        TargetLogonGuid = Properties[7].Value.ToString(),
                                        TargetServerName = Properties[8].Value.ToString(),
                                        TargetInfo = Properties[9].Value.ToString(),
                                        ProcessId = Properties[10].Value.ToString(),
                                        ProcessName = Properties[11].Value.ToString(),
                                        IpAddress = Properties[12].Value.ToString(),
                                        IpPort = Properties[13].Value.ToString()
                                    });
                                }
                                break;
                            default:
                                Logger.Write_Warning($@"No handler exists for event ID: {Event.Id}");
                                break;
                        }
                    }

                    if (Events.Count >= args.MaxEvents)
                        break;
                }
            }
            return Events;
        }

    }
}
