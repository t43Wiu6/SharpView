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
    class GetForest
    { 
        public static ForestEx Get_Forest(Args_Get_Forest args = null)
        {
            if (args == null) args = new Args_Get_Forest();

            var ForestObject = new ForestEx();
            if (args.Credential != null)
            {

                Logger.Write_Verbose(@"[Get-Forest] Using alternate credentials for Get-Forest");

                string TargetForest = null;
                if (args.Forest.IsNotNullOrEmpty())
                {
                    TargetForest = args.Forest;
                }
                else
                {
                    // if no domain is supplied, extract the logon domain from the PSCredential passed
                    TargetForest = args.Credential.Domain;
                    Logger.Write_Verbose(@"[Get-Forest] Extracted domain '$Forest' from -Credential");
                }

                var ForestContext = new System.DirectoryServices.ActiveDirectory.DirectoryContext(System.DirectoryServices.ActiveDirectory.DirectoryContextType.Forest, TargetForest, args.Credential.UserName, args.Credential.Password);

                try
                {
                    ForestObject.Forest = System.DirectoryServices.ActiveDirectory.Forest.GetForest(ForestContext);
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-Forest] The specified forest '{TargetForest}' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: {e}");
                }
            }
            else if (args.Forest.IsNotNullOrEmpty())
            {
                var ForestContext = new System.DirectoryServices.ActiveDirectory.DirectoryContext(System.DirectoryServices.ActiveDirectory.DirectoryContextType.Forest, args.Forest);
                try
                {
                    ForestObject.Forest = System.DirectoryServices.ActiveDirectory.Forest.GetForest(ForestContext);
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-Forest] The specified forest '{args.Forest}' does not exist, could not be contacted, or there isn't an existing trust: {e}");
                }
            }
            else
            {
                // otherwise use the current forest
                ForestObject.Forest = System.DirectoryServices.ActiveDirectory.Forest.GetCurrentForest();
            }

            if (ForestObject.Forest != null)
            {
                // get the SID of the forest root
                string ForestSid = null;
                if (args.Credential != null)
                {
                    ForestSid = (GetDomainUser.Get_DomainUser(new Args_Get_DomainUser { Identity = new[] { @"krbtgt" }, Domain = ForestObject.Forest.RootDomain.Name, Credential = args.Credential }).First() as LDAPProperty).objectsid?.First();
                }
                else
                {
                    ForestSid = (GetDomainUser.Get_DomainUser(new Args_Get_DomainUser { Identity = new[] { @"krbtgt" }, Domain = ForestObject.Forest.RootDomain.Name }).First() as LDAPProperty).objectsid?.First();
                }

                var Parts = ForestSid.Split('-');
                ForestSid = string.Join(@"-", Parts.Take(Parts.Length - 2 + 1));
                ForestObject.RootDomainSid = ForestSid;
                return ForestObject;
            }
            return null;
        }

    }
}
