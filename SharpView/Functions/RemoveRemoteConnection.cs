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
    class RemoveRemoteConnection
    { 
        public static void Remove_RemoteConnection(Args_Remove_RemoteConnection args = null)
        {
            if (args == null) args = new Args_Remove_RemoteConnection();

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
                Logger.Write_Verbose($@"[Remove-RemoteConnection] Attempting to unmount: {TargetPath}");
                var Result = NativeMethods.WNetCancelConnection2(TargetPath, 0, true);

                if (Result == 0)
                {
                    Logger.Write_Verbose($@"{TargetPath} successfully ummounted");
                }
                else
                {
                    throw new Exception($@"[Add-RemoteConnection] error mounting {TargetPath} : {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }
        }

    }
}
