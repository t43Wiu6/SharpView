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
    class ExportPowerViewCSV
    {
        private static string ToCsv<T>(string separator, IEnumerable<T> objectlist)
        {
            Type t = typeof(T);
            FieldInfo[] fields = t.GetFields();
            string header = String.Join(separator, fields.Select(f => f.Name).ToArray());
            StringBuilder csvdata = new StringBuilder();
            csvdata.AppendLine(header);
            foreach (var o in objectlist)
                csvdata.AppendLine(ToCsvFields(separator, fields, o));
            return csvdata.ToString();
        }



        private static string ToCsvFields(string separator, FieldInfo[] fields, object o)
        {
            StringBuilder linie = new StringBuilder();
            foreach (var f in fields)
            {
                if (linie.Length > 0)
                    linie.Append(separator);
                var x = f.GetValue(o);
                if (x != null)
                    linie.Append(x.ToString());
            }
            return linie.ToString();
        }

        public static void Export_PowerViewCSV(Args_Export_PowerViewCSV args = null)
        {
            if (args == null) args = new Args_Export_PowerViewCSV();

            var OutputPath = Path.GetFullPath(args.Path);
            var Exists = File.Exists(OutputPath);

            // mutex so threaded code doesn't stomp on the output file
            var Mutex = new System.Threading.Mutex(false, "CSVMutex");
            Mutex.WaitOne();

            FileMode FileMode;
            if (args.Append)
            {
                FileMode = System.IO.FileMode.Append;
            }
            else
            {
                FileMode = System.IO.FileMode.Create;
                Exists = false;
            }

            var CSVStream = new FileStream(OutputPath, FileMode, System.IO.FileAccess.Write, FileShare.Read);
            var CSVWriter = new System.IO.StreamWriter(CSVStream);
            CSVWriter.AutoFlush = true;

            var csv = ToCsv<object>(args.Delimiter.ToString(), args.InputObject);

            CSVWriter.Write(csv);

            Mutex.ReleaseMutex();
            CSVWriter.Dispose();
            CSVStream.Dispose();
        }
        
        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<string> _Find_LocalAdminAccess(string[] ComputerName, IntPtr TokenHandle)
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

            var TargetComputers = new List<string>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up) {
                    // check if the current user has local admin access to this server
                    var Access = TestAdminAccess.Test_AdminAccess(new Args_Test_AdminAccess { ComputerName = new[] { TargetComputer } }).FirstOrDefault();
                    if (Access != null && Access.IsAdmin) {
                        TargetComputers.Add(TargetComputer);
                    }
                }
            }

            if (TokenHandle != IntPtr.Zero) {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }
            return TargetComputers;
        }

    }
}
