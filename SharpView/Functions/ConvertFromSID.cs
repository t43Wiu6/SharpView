using System;
using System.Collections.Generic;
using SharpView.Arguments;
using SharpView.Utils;

namespace SharpView.Functions
{ 
    class ConvertFromSID
    { 
        public static IEnumerable<string> ConvertFrom_SID(Args_ConvertFrom_SID args = null)
        {
            if (args == null) args = new Args_ConvertFrom_SID();

            var ADNameArguments = new Args_Convert_ADName
            {
                Domain = args.Domain,
                Server = args.Server,
                Credential = args.Credential
            };

            var Results = new List<string>();
            foreach (var TargetSid in args.ObjectSID)
            {
                var trimedTargetSid = TargetSid.Trim('*');
                try
                {
                    // try to resolve any built-in SIDs first - https://support.microsoft.com/en-us/kb/243330

                    if (trimedTargetSid == @"S-1-0") { Results.Add(@"Null Authority"); }
                    else if (trimedTargetSid == @"S -1-0-0") { Results.Add(@"Nobody"); }
                    else if (trimedTargetSid == @"S-1-1") { Results.Add(@"World Authority"); }
                    else if (trimedTargetSid == @"S-1-1-0") { Results.Add(@"Everyone"); }
                    else if (trimedTargetSid == @"S-1-2") { Results.Add(@"Local Authority"); }
                    else if (trimedTargetSid == @"S-1-2-0") { Results.Add(@"Local"); }
                    else if (trimedTargetSid == @"S-1-2-1") { Results.Add(@"Console Logon "); }
                    else if (trimedTargetSid == @"S-1-3") { Results.Add(@"Creator Authority"); }
                    else if (trimedTargetSid == @"S-1-3-0") { Results.Add(@"Creator Owner"); }
                    else if (trimedTargetSid == @"S-1-3-1") { Results.Add(@"Creator Group"); }
                    else if (trimedTargetSid == @"S-1-3-2") { Results.Add(@"Creator Owner Server"); }
                    else if (trimedTargetSid == @"S-1-3-3") { Results.Add(@"Creator Group Server"); }
                    else if (trimedTargetSid == @"S-1-3-4") { Results.Add(@"Owner Rights"); }
                    else if (trimedTargetSid == @"S-1-4") { Results.Add(@"Non-unique Authority"); }
                    else if (trimedTargetSid == @"S-1-5") { Results.Add(@"NT Authority"); }
                    else if (trimedTargetSid == @"S-1-5-1") { Results.Add(@"Dialup"); }
                    else if (trimedTargetSid == @"S-1-5-2") { Results.Add(@"Network"); }
                    else if (trimedTargetSid == @"S-1-5-3") { Results.Add(@"Batch"); }
                    else if (trimedTargetSid == @"S-1-5-4") { Results.Add(@"Interactive"); }
                    else if (trimedTargetSid == @"S-1-5-6") { Results.Add(@"Service"); }
                    else if (trimedTargetSid == @"S-1-5-7") { Results.Add(@"Anonymous"); }
                    else if (trimedTargetSid == @"S-1-5-8") { Results.Add(@"Proxy"); }
                    else if (trimedTargetSid == @"S-1-5-9") { Results.Add(@"Enterprise Domain Controllers"); }
                    else if (trimedTargetSid == @"S-1-5-10") { Results.Add(@"Principal Self"); }
                    else if (trimedTargetSid == @"S-1-5-11") { Results.Add(@"Authenticated Users"); }
                    else if (trimedTargetSid == @"S-1-5-12") { Results.Add(@"Restricted Code"); }
                    else if (trimedTargetSid == @"S-1-5-13") { Results.Add(@"Terminal Server Users"); }
                    else if (trimedTargetSid == @"S-1-5-14") { Results.Add(@"Remote Interactive Logon"); }
                    else if (trimedTargetSid == @"S-1-5-15") { Results.Add(@"This Organization "); }
                    else if (trimedTargetSid == @"S-1-5-17") { Results.Add(@"This Organization "); }
                    else if (trimedTargetSid == @"S-1-5-18") { Results.Add(@"Local System"); }
                    else if (trimedTargetSid == @"S-1-5-19") { Results.Add(@"NT Authority"); }
                    else if (trimedTargetSid == @"S-1-5-20") { Results.Add(@"NT Authority"); }
                    else if (trimedTargetSid == @"S-1-5-80-0") { Results.Add(@"All Services "); }
                    else if (trimedTargetSid == @"S-1-5-32-544") { Results.Add(@"BUILTIN\Administrators"); }
                    else if (trimedTargetSid == @"S-1-5-32-545") { Results.Add(@"BUILTIN\Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-546") { Results.Add(@"BUILTIN\Guests"); }
                    else if (trimedTargetSid == @"S-1-5-32-547") { Results.Add(@"BUILTIN\Power Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-548") { Results.Add(@"BUILTIN\Account Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-549") { Results.Add(@"BUILTIN\Server Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-550") { Results.Add(@"BUILTIN\Print Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-551") { Results.Add(@"BUILTIN\Backup Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-552") { Results.Add(@"BUILTIN\Replicators"); }
                    else if (trimedTargetSid == @"S-1-5-32-554") { Results.Add(@"BUILTIN\Pre-Windows 2000 Compatible Access"); }
                    else if (trimedTargetSid == @"S-1-5-32-555") { Results.Add(@"BUILTIN\Remote Desktop Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-556") { Results.Add(@"BUILTIN\Network Configuration Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-557") { Results.Add(@"BUILTIN\Incoming Forest Trust Builders"); }
                    else if (trimedTargetSid == @"S-1-5-32-558") { Results.Add(@"BUILTIN\Performance Monitor Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-559") { Results.Add(@"BUILTIN\Performance Log Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-560") { Results.Add(@"BUILTIN\Windows Authorization Access Group"); }
                    else if (trimedTargetSid == @"S-1-5-32-561") { Results.Add(@"BUILTIN\Terminal Server License Servers"); }
                    else if (trimedTargetSid == @"S-1-5-32-562") { Results.Add(@"BUILTIN\Distributed COM Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-569") { Results.Add(@"BUILTIN\Cryptographic Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-573") { Results.Add(@"BUILTIN\Event Log Readers"); }
                    else if (trimedTargetSid == @"S-1-5-32-574") { Results.Add(@"BUILTIN\Certificate Service DCOM Access"); }
                    else if (trimedTargetSid == @"S-1-5-32-575") { Results.Add(@"BUILTIN\RDS Remote Access Servers"); }
                    else if (trimedTargetSid == @"S-1-5-32-576") { Results.Add(@"BUILTIN\RDS Endpoint Servers"); }
                    else if (trimedTargetSid == @"S-1-5-32-577") { Results.Add(@"BUILTIN\RDS Management Servers"); }
                    else if (trimedTargetSid == @"S-1-5-32-578") { Results.Add(@"BUILTIN\Hyper-V Administrators"); }
                    else if (trimedTargetSid == @"S-1-5-32-579") { Results.Add(@"BUILTIN\Access Control Assistance Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-580") { Results.Add(@"BUILTIN\Access Control Assistance Operators"); }
                    else
                    {
                        ADNameArguments.Identity = new string[] { TargetSid };
                        Results.AddRange(ConvertADName.Convert_ADName(ADNameArguments));
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[ConvertFrom-SID] Error converting SID '{TargetSid}' : {e}");
                }
            }
            return Results;
        }

    }
}
