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
    class GetWMIRegProxy
    { 
        public static IEnumerable<ProxySettings> Get_WMIRegProxy(Args_Get_WMIRegProxy args = null)
        {
            if (args == null) args = new Args_Get_WMIRegProxy();

            var ProxySettings = new List<ProxySettings>();
            foreach (var Computer in args.ComputerName)
            {
                try
                {
                    var RegProvider = WmiWrapper.GetClass($@"\\{Computer}\ROOT\DEFAULT", "StdRegProv", args.Credential);
                    var Key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";

                    // HKEY_CURRENT_USER
                    var HKCU = 2147483649;
                    var outParams = WmiWrapper.CallMethod(RegProvider, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKCU }, { "sSubKeyName", Key }, { "sValueName", "ProxyServer" } }) as System.Management.ManagementBaseObject;
                    var ProxyServer = outParams["sValue"] as string;
                    outParams = WmiWrapper.CallMethod(RegProvider, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKCU }, { "sSubKeyName", Key }, { "sValueName", "AutoConfigURL" } }) as System.Management.ManagementBaseObject;
                    var AutoConfigURL = outParams["sValue"] as string;

                    var Wpad = "";
                    if (AutoConfigURL != null && AutoConfigURL != "")
                    {
                        try
                        {
                            Wpad = (new System.Net.WebClient()).DownloadString(AutoConfigURL);
                        }
                        catch
                        {
                            Logger.Write_Warning($@"[Get-WMIRegProxy] Error connecting to AutoConfigURL : {AutoConfigURL}");
                        }
                    }

                    if (ProxyServer != null || AutoConfigURL != null)
                    {
                        var Out = new ProxySettings
                        {
                            ComputerName = Computer,
                            ProxyServer = ProxyServer,
                            AutoConfigURL = AutoConfigURL,
                            Wpad = Wpad
                        };
                        ProxySettings.Add(Out);
                    }
                    else
                    {
                        Logger.Write_Warning($@"[Get-WMIRegProxy] No proxy settings found for {Computer}");
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Get-WMIRegProxy] Error enumerating proxy settings for {Computer} : {e}");
                }
            }

            return ProxySettings;
        }

    }
}
