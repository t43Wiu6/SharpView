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
    class AddRemoteConnection
    { 
        public static void Add_RemoteConnection(Args_Add_RemoteConnection args = null)
        {
            if (args == null) args = new Args_Add_RemoteConnection();

            var NetResourceInstance = Activator.CreateInstance(typeof(NetResource)) as NetResource;
            NetResourceInstance.ResourceType = NativeMethods.ResourceType.Disk;

            var Paths = new List<string>();
            if (args.ComputerName != null)
            {
                foreach (var item in args.ComputerName)
                {
                    var TargetComputerName = item;
                    TargetComputerName = TargetComputerName.Trim('\\');
                    Paths.Add($@"\\{TargetComputerName}\IPC$");
                }
            }
            else
            {
                Paths.AddRange(args.Path);
            }

            foreach (var TargetPath in Paths)
            {
                NetResourceInstance.RemoteName = TargetPath;
                Logger.Write_Verbose($@"[Add-RemoteConnection] Attempting to mount: {TargetPath}");

                // https://msdn.microsoft.com/en-us/library/windows/desktop/aa385413(v=vs.85).aspx
                //   CONNECT_TEMPORARY = 4
                var Result = NativeMethods.WNetAddConnection2(NetResourceInstance, args.Credential.Password, args.Credential.UserName, 4);

                if (Result == 0)
                {
                    Logger.Write_Verbose($@"{TargetPath} successfully mounted");
                }
                else
                {
                    throw new Exception($@"[Add-RemoteConnection] error mounting {TargetPath} : {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }
        }

    }
}
