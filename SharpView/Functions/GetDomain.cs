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
    class GetDomain
    { 
        public static System.DirectoryServices.ActiveDirectory.Domain Get_Domain(Args_Get_Domain args = null)
        {
            if (args == null) args = new Args_Get_Domain();

            if (args.Credential != null)
            {
                Logger.Write_Verbose("[Get-Domain] Using alternate credentials for Get-Domain");

                string TargetDomain;
                if (args.Domain.IsNotNullOrEmpty())
                {
                    TargetDomain = args.Domain;
                }
                else
                {
                    // if no domain is supplied, extract the logon domain from the PSCredential passed
                    TargetDomain = args.Credential.Domain;
                    Logger.Write_Verbose("[Get-Domain] Extracted domain '$TargetDomain' from -Credential");
                }

                var DomainContext = new System.DirectoryServices.ActiveDirectory.DirectoryContext(System.DirectoryServices.ActiveDirectory.DirectoryContextType.Domain,
                    TargetDomain,
                    args.Credential.UserName,
                    args.Credential.Password);

                try
                {
                    return System.DirectoryServices.ActiveDirectory.Domain.GetDomain(DomainContext);
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($"[Get-Domain] The specified domain '{TargetDomain}' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: {e}");
                }
            }
            else if (args.Domain.IsNotNullOrEmpty())
            {
                var DomainContext = new System.DirectoryServices.ActiveDirectory.DirectoryContext(System.DirectoryServices.ActiveDirectory.DirectoryContextType.Domain, args.Domain);
                try
                {
                    return System.DirectoryServices.ActiveDirectory.Domain.GetDomain(DomainContext);
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($"[Get-Domain] The specified domain '{args.Domain}' does not exist, could not be contacted, or there isn't an existing trust : {e}");
                }
            }
            else
            {
                try
                {
                    return System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                }
                catch (ActiveDirectoryOperationException err)
                {
                    Logger.Write_Verbose($"[Get-Domain] Error retrieving the current domain, Maybe not in domain");
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($"[Get-Domain] Error retrieving the current domain: {e}");
                }
            }
            return null;
        }

    }
}
