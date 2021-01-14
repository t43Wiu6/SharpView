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
    class GetDomainController
    { 
        public static IEnumerable<object> Get_DomainController(Args_Get_DomainController args = null)
        {
            if (args == null) args = new Args_Get_DomainController();

            var Arguments = new Args_Get_DomainComputer();

            if (args.Domain.IsNotNullOrEmpty()) { Arguments.Domain = args.Domain; }
            if (args.Credential != null) { Arguments.Credential = args.Credential; }

            if (args.LDAP || args.Server.IsNotNullOrEmpty())
            {
                if (args.Server.IsNotNullOrEmpty()) { Arguments.Server = args.Server; }

                // UAC specification for domain controllers
                Arguments.LDAPFilter = @"(userAccountControl:1.2.840.113556.1.4.803:=8192)";

                return GetDomainComputer.Get_DomainComputer(Arguments);
            }
            else
            {
                var FoundDomain = GetDomain.Get_Domain(new Args_Get_Domain
                {
                    Domain = Arguments.Domain,
                    Credential = Arguments.Credential
                });
                if (FoundDomain != null)
                {
                    var controllers = new List<object>();
                    foreach (var controller in FoundDomain.DomainControllers)
                    {
                        controllers.Add(controller);
                    }
                    return controllers;
                }
            }
            return null;
        }

    }
}
