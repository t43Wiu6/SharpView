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
    class GetWMIRegMountedDrive
    { 
        public static IEnumerable<RegMountedDrive> Get_WMIRegMountedDrive(Args_Get_WMIRegMountedDrive args = null)
        {
            if (args == null) args = new Args_Get_WMIRegMountedDrive();

            var MountedDrives = new List<RegMountedDrive>();
            foreach (var Computer in args.ComputerName)
            {
                // HKEY_USERS
                var HKU = 2147483651;
                try
                {
                    var Reg = WmiWrapper.GetClass($@"\\{Computer}\ROOT\DEFAULT", "StdRegProv", args.Credential);

                    // extract out the SIDs of domain users in this hive
                    var outParams = WmiWrapper.CallMethod(Reg, "EnumKey", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", "" } }) as System.Management.ManagementBaseObject;
                    var names = outParams["sNames"] as IEnumerable<string>;
                    if (names == null) continue;

                    var UserSIDs = names.Where(x => x.IsRegexMatch($@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"));

                    foreach (var UserSID in UserSIDs)
                    {
                        try
                        {
                            var UserName = ConvertFromSID.ConvertFrom_SID(new Args_ConvertFrom_SID { ObjectSID = new[] { UserSID }, Credential = args.Credential }).FirstOrDefault();
                            outParams = WmiWrapper.CallMethod(Reg, "EnumKey", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Network" } }) as System.Management.ManagementBaseObject;
                            var DriveLetters = outParams["sNames"] as IEnumerable<string>;
                            if (DriveLetters == null) continue;

                            foreach (var DriveLetter in DriveLetters)
                            {
                                outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Network\{DriveLetter}" }, { "sValueName", "ProviderName" } }) as System.Management.ManagementBaseObject;
                                var ProviderName = outParams["sValue"] as string;
                                outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Network\{DriveLetter}" }, { "sValueName", "RemotePath" } }) as System.Management.ManagementBaseObject;
                                var RemotePath = outParams["sValue"] as string;
                                outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Network\{DriveLetter}" }, { "sValueName", "UserName" } }) as System.Management.ManagementBaseObject;
                                var DriveUserName = outParams["sValue"] as string;
                                if (UserName == null) { UserName = ""; }

                                if (RemotePath != null && (RemotePath != ""))
                                {
                                    var MountedDrive = new RegMountedDrive
                                    {
                                        ComputerName = Computer,
                                        UserName = UserName,
                                        UserSID = UserSID,
                                        DriveLetter = DriveLetter,
                                        ProviderName = ProviderName,
                                        RemotePath = RemotePath,
                                        DriveUserName = DriveUserName
                                    };
                                    MountedDrives.Add(MountedDrive);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-WMIRegMountedDrive] Error: {e}");
                        }
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Get-WMIRegMountedDrive] Error accessing {Computer}, likely insufficient permissions or firewall rules on host: {e}");
                }
            }
            return MountedDrives;
        }

    }
}
