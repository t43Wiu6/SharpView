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
    class ConvertFromUACValue
    { 
        public static System.Collections.Specialized.OrderedDictionary ConvertFrom_UACValue(Args_ConvertFrom_UACValue args = null)
        {
            if (args == null) args = new Args_ConvertFrom_UACValue();

            // values from https://support.microsoft.com/en-us/kb/305144
            var UACValues = new System.Collections.Specialized.OrderedDictionary();
            UACValues.Add("SCRIPT", 1);
            UACValues.Add("ACCOUNTDISABLE", 2);
            UACValues.Add("HOMEDIR_REQUIRED", 8);
            UACValues.Add("LOCKOUT", 16);
            UACValues.Add("PASSWD_NOTREQD", 32);
            UACValues.Add("PASSWD_CANT_CHANGE", 64);
            UACValues.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128);
            UACValues.Add("TEMP_DUPLICATE_ACCOUNT", 256);
            UACValues.Add("NORMAL_ACCOUNT", 512);
            UACValues.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048);
            UACValues.Add("WORKSTATION_TRUST_ACCOUNT", 4096);
            UACValues.Add("SERVER_TRUST_ACCOUNT", 8192);
            UACValues.Add("DONT_EXPIRE_PASSWORD", 65536);
            UACValues.Add("MNS_LOGON_ACCOUNT", 131072);
            UACValues.Add("SMARTCARD_REQUIRED", 262144);
            UACValues.Add("TRUSTED_FOR_DELEGATION", 524288);
            UACValues.Add("NOT_DELEGATED", 1048576);
            UACValues.Add("USE_DES_KEY_ONLY", 2097152);
            UACValues.Add("DONT_REQ_PREAUTH", 4194304);
            UACValues.Add("PASSWORD_EXPIRED", 8388608);
            UACValues.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216);
            UACValues.Add("PARTIAL_SECRETS_ACCOUNT", 67108864);

            var ResultUACValues = new System.Collections.Specialized.OrderedDictionary();

            if (args.ShowAll)
            {
                foreach (DictionaryEntry UACValue in UACValues)
                {
                    if ((args.Value & (int)UACValue.Value) == (int)UACValue.Value)
                    {
                        ResultUACValues.Add(UACValue.Key, $"{UACValue.Value}+");
                    }
                    else
                    {
                        ResultUACValues.Add(UACValue.Key, $"{UACValue.Value}");
                    }
                }
            }
            else
            {
                foreach (DictionaryEntry UACValue in UACValues)
                {
                    if ((args.Value & (int)UACValue.Value) == (int)UACValue.Value)
                    {
                        ResultUACValues.Add(UACValue.Key, $"{UACValue.Value}");
                    }
                }
            }
            return ResultUACValues;
        }

    }
}
