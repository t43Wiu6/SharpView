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
    class GetNetComputerSiteName
    { 
        public static IEnumerable<ComputerSite> Get_NetComputerSiteName(Args_Get_NetComputerSiteName args = null)
        {
            if (args == null) args = new Args_Get_NetComputerSiteName();
            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation { Credential = args.Credential });
            }

            var ComputerSites = new List<ComputerSite>();
            foreach (var item in args.ComputerName)
            {
                string IPAddress;
                var Computer = item;
                //if we get an IP address, try to resolve the IP to a hostname
                if (Computer.IsRegexMatch(@"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"))
                {
                    IPAddress = Computer;
                    Computer = System.Net.Dns.GetHostEntry(Computer).HostName;
                }
                else
                {
                    IPAddress = ResolveIPAddress.Resolve_IPAddress(new Args_Resolve_IPAddress { ComputerName = new[] { Computer } }).First().IPAddress;
                }

                var PtrInfo = IntPtr.Zero;

                var Result = NativeMethods.DsGetSiteName(Computer, out PtrInfo);

                var ComputerSite = new ComputerSite
                {
                    ComputerName = Computer,
                    IPAddress = IPAddress
                };

                if (Result == 0)
                {
                    var Sitename = System.Runtime.InteropServices.Marshal.PtrToStringAuto(PtrInfo);
                    ComputerSite.SiteName = Sitename;
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-NetComputerSiteName] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");

                    ComputerSite.SiteName = @"";
                }

                // free up the result buffer
                NativeMethods.NetApiBufferFree(PtrInfo);

                ComputerSites.Add(ComputerSite);
            }
            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return ComputerSites;
        }

    }
}
