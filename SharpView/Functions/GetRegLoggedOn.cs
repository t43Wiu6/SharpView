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
    class GetRegLoggedOn
    { 
        public static IEnumerable<RegLoggedOnUser> Get_RegLoggedOn(Args_Get_RegLoggedOn args = null)
        {
            if (args == null) args = new Args_Get_RegLoggedOn();

            IntPtr LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = InvokeUserImpersonation.Invoke_UserImpersonation(new Args_Invoke_UserImpersonation { Credential = args.Credential });
            }

            var RegLoggedOnUsers = new List<RegLoggedOnUser>();
            foreach (var Computer in args.ComputerName)
            {
                try
                {
                    // retrieve HKU remote registry values
                    var Reg = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(Microsoft.Win32.RegistryHive.Users, $@"{Computer}");

                    // sort out bogus sid's like _class
                    var subkeys = Reg.GetSubKeyNames()?.Where(x => x.IsRegexMatch(@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"));

                    foreach (var subkey in subkeys)
                    {
                        var UserName = ConvertFromSID.ConvertFrom_SID(new Args_ConvertFrom_SID { ObjectSID = new[] { subkey } }).FirstOrDefault();
                        string UserDomain;

                        if (UserName != null)
                        {
                            UserName = UserName.Split('@')[0];
                            UserDomain = UserName.Split('@')[1];
                        }
                        else
                        {
                            UserName = subkey;
                            UserDomain = null;
                        }

                        var RegLoggedOnUser = new RegLoggedOnUser
                        {
                            ComputerName = $@"{Computer}",
                            UserDomain = UserDomain,
                            UserName = UserName,
                            UserSID = subkey
                        };
                        RegLoggedOnUsers.Add(RegLoggedOnUser);
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-RegLoggedOn] Error opening remote registry on '{Computer}' : {e}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                InvokeRevertToSelf.Invoke_RevertToSelf(LogonToken);
            }

            return RegLoggedOnUsers;
        }

    }
}
