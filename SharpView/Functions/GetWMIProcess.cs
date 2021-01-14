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
    class GetWMIProcess
    { 
        public static IEnumerable<UserProcess> Get_WMIProcess(Args_Get_WMIProcess args = null)
        {
            if (args == null) args = new Args_Get_WMIProcess();

            var UserProcesses = new List<UserProcess>();
            foreach (var Computer in args.ComputerName)
            {
                try
                {
                    var cls = WmiWrapper.GetClass($@"\\{Computer}\ROOT\CIMV2", "Win32_process", args.Credential);
                    var procs = WmiWrapper.GetInstances(cls);
                    foreach (var proc in procs)
                    {
                        var owner = WmiWrapper.CallMethod(proc, "GetOwner");
                        var UserProcess = new UserProcess
                        {
                            ComputerName = Computer,
                            ProcessName = proc.Properties["Caption"].Value.ToString(),
                            ProcessID = proc.Properties["ProcessId"].Value.ToString(),
                            Domain = $@"{owner["Domain"]}",
                            User = $@"{owner["User"]}",
                        };
                        UserProcesses.Add(UserProcess);
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-WMIProcess] Error enumerating remote processes on '{Computer}', access likely denied: {e}");
                }
            }
            return UserProcesses;
        }

    }
}
