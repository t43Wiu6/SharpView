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
    class GetDomainFileServer
    {
        private static string Split_Path(string Path)
        {
            if (Path.IsNotNullOrEmpty() && Path.Split(new char[] { '\\' }).Length >= 3)
            {
                var Temp = Path.Split('\\')[2];
                if (Temp != null && Temp != "")
                {
                    return Temp;
                }
            }
            return null;
        }

        public static string[] Get_DomainFileServer(Args_Get_DomainFileServer args = null)
        {
            if (args == null) args = new Args_Get_DomainFileServer();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                LDAPFilter = "(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))",
                Properties = new string[] { "homedirectory", "scriptpath", "profilepath" },
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var retValues = new List<string>();

            if (args.Domain != null)
            {
                foreach (var TargetDomain in args.Domain)
                {
                    SearcherArguments.Domain = TargetDomain;
                    var UserSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                    // get all results w/o the pipeline and uniquify them (I know it's not pretty)
                    foreach (SearchResult UserResult in UserSearcher.FindAll())
                    {
                        if (UserResult.Properties["homedirectory"] != null)
                        {
                            var val = Split_Path(UserResult.Properties["homedirectory"][0] as string);
                            if (!retValues.Any(x => x == val)) retValues.Add(val);
                        }
                        if (UserResult.Properties["scriptpath"] != null)
                        {
                            var val = Split_Path(UserResult.Properties["scriptpath"][0] as string);
                            if (!retValues.Any(x => x == val)) retValues.Add(val);
                        }
                        if (UserResult.Properties["profilepath"] != null)
                        {
                            var val = Split_Path(UserResult.Properties["profilepath"][0] as string);
                            if (!retValues.Any(x => x == val)) retValues.Add(val);
                        }
                    }
                }
            }
            else
            {
                var UserSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);
                // get all results w/o the pipeline and uniquify them (I know it's not pretty)
                foreach (SearchResult UserResult in UserSearcher.FindAll())
                {
                    if (UserResult.Properties["homedirectory"] != null)
                    {
                        var val = Split_Path(UserResult.Properties["homedirectory"][0] as string);
                        if (!retValues.Any(x => x == val)) retValues.Add(val);
                    }
                    if (UserResult.Properties["scriptpath"] != null)
                    {
                        var val = Split_Path(UserResult.Properties["scriptpath"][0] as string);
                        if (!retValues.Any(x => x == val)) retValues.Add(val);
                    }
                    if (UserResult.Properties["profilepath"] != null)
                    {
                        var val = Split_Path(UserResult.Properties["profilepath"][0] as string);
                        if (!retValues.Any(x => x == val)) retValues.Add(val);
                    }
                }
            }
            return retValues.ToArray();
        }

    }
}
