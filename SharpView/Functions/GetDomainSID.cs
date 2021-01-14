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
    class GetDomainSID
    { 
        public static string Get_DomainSID(Args_Get_DomainSID args = null)
        {
            if (args == null) args = new Args_Get_DomainSID();

            var SearcherArguments = new Args_Get_DomainComputer
            {
                LDAPFilter = @"(userAccountControl:1.2.840.113556.1.4.803:=8192)",
                Domain = args.Domain,
                Server = args.Server,
                Credential = args.Credential,
                FindOne = true
            };

            var computer = GetDomainComputer.Get_DomainComputer(SearcherArguments).First() as LDAPProperty;
            var DCSIDs = computer.objectsid;

            if (DCSIDs != null)
            {
                return DCSIDs[0]?.Substring(0, DCSIDs[0].LastIndexOf('-'));
            }
            else
            {
                Logger.Write_Verbose($@"[Get-DomainSID] Error extracting domain SID for '{args.Domain}'");
            }
            return null;
        }

    }
}
