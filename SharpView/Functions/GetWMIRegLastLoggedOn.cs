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
    class GetWMIRegLastLoggedOn
    { 
        public static IEnumerable<LastLoggedOnUser> Get_WMIRegLastLoggedOn(Args_Get_WMIRegLastLoggedOn args = null)
        {
            if (args == null) args = new Args_Get_WMIRegLastLoggedOn();

            var LastLoggedOnUsers = new List<LastLoggedOnUser>();
            foreach (var Computer in args.ComputerName)
            {
                // HKEY_LOCAL_MACHINE
                var HKLM = 2147483650;

                // try to open up the remote registry key to grab the last logged on user
                try
                {
                    var Reg = WmiWrapper.GetClass($@"\\{Computer}\ROOT\DEFAULT", "StdRegProv", args.Credential);
                    var Key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI";

                    var Value = "LastLoggedOnUser";
                    var outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKLM }, { "sSubKeyName", Key }, { "sValueName", Value } }) as System.Management.ManagementBaseObject;
                    var LastUser = outParams["sValue"] as string;

                    var LastLoggedOn = new LastLoggedOnUser
                    {
                        ComputerName = Computer,
                        LastLoggedOn = LastUser
                    };
                    LastLoggedOnUsers.Add(LastLoggedOn);
                }
                catch
                {
                    Logger.Write_Warning("[Get-WMIRegLastLoggedOn] Error opening remote registry on $Computer. Remote registry likely not enabled.");
                }
            }
            return LastLoggedOnUsers;
        }

    }
}
