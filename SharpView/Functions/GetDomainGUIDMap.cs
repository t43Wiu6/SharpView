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
    class GetDomainGUIDMap
    { 
        public static Dictionary<string, string> Get_DomainGUIDMap(Args_Get_DomainGUIDMap args = null)
        {
            if (args == null) args = new Args_Get_DomainGUIDMap();

            var GUIDs = new Dictionary<string, string>
            {
                { @"00000000-0000-0000-0000-000000000000", @"All"}
            };

            var ForestArguments = new Args_Get_Forest()
            {
                Credential = args.Credential
            };

            string SchemaPath = null;
            try
            {
                SchemaPath = GetForest.Get_Forest(ForestArguments).Forest.Schema.Name;
            }
            catch
            {
                throw new Exception(@"[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest");
            }
            if (SchemaPath.IsNullOrEmpty())
            {
                throw new Exception(@"[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest");
            }

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                SearchBase = SchemaPath,
                LDAPFilter = @"(schemaIDGUID=*)",
                Domain = args.Domain,
                Server = args.Server,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Credential = args.Credential
            };
            var SchemaSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);

            if (SchemaSearcher != null)
            {
                try
                {
                    var Results = SchemaSearcher.FindAll();
                    if (Results != null)
                    {
                        foreach (SearchResult result in Results)
                        {
                            GUIDs[(new Guid(result.Properties["schemaidguid"][0] as byte[])).ToString()] = result.Properties["name"][0].ToString();
                        }
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainGUIDMap] Error disposing of the Results object: {e}");
                        }
                    }
                    SchemaSearcher.Dispose();
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-DomainGUIDMap] Error in building GUID map: {e}");
                }
            }

            SearcherArguments.SearchBase = SchemaPath.Replace(@"Schema", @"Extended-Rights");
            SearcherArguments.LDAPFilter = @"(objectClass=controlAccessRight)";
            var RightsSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);

            if (RightsSearcher != null)
            {
                try
                {
                    var Results = RightsSearcher.FindAll();
                    if (Results != null)
                    {
                        foreach (SearchResult result in Results)
                        {
                            GUIDs[(new Guid(result.Properties["rightsguid"][0] as byte[])).ToString()] = result.Properties["name"][0].ToString();
                        }
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainGUIDMap] Error disposing of the Results object: {e}");
                        }
                    }
                    RightsSearcher.Dispose();
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-DomainGUIDMap] Error in building GUID map: {e}");
                }
            }
            return GUIDs;
        }

    }
}
