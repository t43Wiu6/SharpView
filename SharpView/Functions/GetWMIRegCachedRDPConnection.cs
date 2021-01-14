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
    class GetWMIRegCachedRDPConnection
    { 
        public static IEnumerable<CachedRDPConnection> Get_WMIRegCachedRDPConnection(Args_Get_WMIRegCachedRDPConnection args = null)
        {
            if (args == null) args = new Args_Get_WMIRegCachedRDPConnection();

            var FoundConnections = new List<CachedRDPConnection>();
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

                            // pull out all the cached RDP connections
                            outParams = WmiWrapper.CallMethod(Reg, "EnumValues", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Software\Microsoft\Terminal Server Client\Default" } }) as System.Management.ManagementBaseObject;
                            var ConnectionKeys = outParams["sNames"] as IEnumerable<string>;

                            if (ConnectionKeys != null)
                            {
                                foreach (var Connection in ConnectionKeys)
                                {
                                    // make sure this key is a cached connection
                                    if (Connection.IsRegexMatch(@"MRU.*"))
                                    {
                                        outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Software\Microsoft\Terminal Server Client\Default" }, { "sValueName", Connection } }) as System.Management.ManagementBaseObject;
                                        var TargetServer = outParams["sValue"] as string;

                                        var FoundConnection = new CachedRDPConnection
                                        {
                                            ComputerName = Computer,
                                            UserName = UserName,
                                            UserSID = UserSID,
                                            TargetServer = TargetServer,
                                            UsernameHint = null
                                        };
                                        FoundConnections.Add(FoundConnection);
                                    }
                                }
                            }

                            // pull out all the cached server info with username hints
                            outParams = WmiWrapper.CallMethod(Reg, "EnumKey", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Software\Microsoft\Terminal Server Client\Servers" } }) as System.Management.ManagementBaseObject;
                            var ServerKeys = outParams["sNames"] as IEnumerable<string>;

                            if (ServerKeys != null)
                            {
                                foreach (var Server in ServerKeys)
                                {
                                    outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Software\Microsoft\Terminal Server Client\Servers\{Server}" }, { "sValueName", "UsernameHint" } }) as System.Management.ManagementBaseObject;
                                    var UsernameHint = outParams["sValue"] as string;

                                    var FoundConnection = new CachedRDPConnection
                                    {
                                        ComputerName = Computer,
                                        UserName = UserName,
                                        UserSID = UserSID,
                                        TargetServer = Server,
                                        UsernameHint = UsernameHint
                                    };
                                    FoundConnections.Add(FoundConnection);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-WMIRegCachedRDPConnection] Error: {e}");
                        }
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Get-WMIRegCachedRDPConnection] Error accessing {Computer}, likely insufficient permissions or firewall rules on host: {e}");
                }
            }
            return FoundConnections;
        }

    }
}
