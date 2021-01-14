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
    class GetPrincipalContext
    { 
        public static PrincipalContextEx Get_PrincipalContext(Args_Get_PrincipalContext args = null)
        {
            if (args == null) args = new Args_Get_PrincipalContext();

            try
            {
                var ConnectTarget = string.Empty;
                var ObjectIdentity = string.Empty;
                System.DirectoryServices.AccountManagement.PrincipalContext Context = null;
                if (!string.IsNullOrEmpty(args.Domain) || args.Identity.IsRegexMatch(@".+\\.+"))
                {
                    if (args.Identity.IsRegexMatch(@".+\\.+"))
                    {
                        // DOMAIN\groupname
                        var ConvertedIdentity = ConvertADName.Convert_ADName(new Args_Convert_ADName { Identity = new[] { args.Identity } }).FirstOrDefault();
                        if (ConvertedIdentity != null)
                        {
                            ConnectTarget = ConvertedIdentity.Substring(0, ConvertedIdentity.IndexOf('/'));
                            ObjectIdentity = args.Identity.Split('\\')[1];
                            Logger.Write_Verbose($@"[Get-PrincipalContext] Binding to domain '{ConnectTarget}'");
                        }
                    }
                    else
                    {
                        ObjectIdentity = args.Identity;
                        Logger.Write_Verbose($@"[Get-PrincipalContext] Binding to domain '{args.Domain}'");
                        ConnectTarget = args.Domain;
                    }

                    if (args.Credential != null)
                    {
                        Logger.Write_Verbose($@"[Get-PrincipalContext] Using alternate credentials");
                        Context = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain, ConnectTarget, args.Credential.UserName, args.Credential.Password);
                    }
                    else
                    {
                        Context = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain, ConnectTarget);
                    }
                }
                else
                {
                    if (args.Credential != null)
                    {
                        Logger.Write_Verbose($@"[Get-PrincipalContext] Using alternate credentials");
                        var DomainName = GetDomain.Get_Domain().Name;
                        Context = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain, DomainName, args.Credential.UserName, args.Credential.Password);
                    }
                    else
                    {
                        Context = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain);
                    }
                    ObjectIdentity = args.Identity;
                }

                return new PrincipalContextEx
                {
                    Context = Context,
                    Identity = ObjectIdentity
                };
            }
            catch (Exception e)
            {
                Logger.Write_Warning($@"[Get-PrincipalContext] Error creating binding for object ('{args.Identity}') context : {e}");
            }

            return null;
        }

    }
}
