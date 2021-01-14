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
    class SetDomainObject
    { 
        public static void Set_DomainObject(Args_Set_DomainObject args = null)
        {
            var SearcherArguments = new Args_Get_DomainObject
            {
                Identity = args.Identity,
                Raw = true,
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            // splat the appropriate arguments to Get-DomainObject
            var RawObject = GetDomainObject.Get_DomainObject(SearcherArguments);

            foreach (SearchResult obj in RawObject)
            {
                var Entry = obj.GetDirectoryEntry();

                if (args.Set != null)
                {
                    try
                    {
                        foreach (var set in args.Set)
                        {
                            Logger.Write_Verbose($@"[Set-DomainObject] Setting '{set.Key}' to '{set.Value}' for object '{obj.Properties[@"samaccountname"][0]}'");

                            Entry.InvokeSet(set.Key, new[] { set.Value });
                        }
                        Entry.CommitChanges();
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Set-DomainObject] Error setting/replacing properties for object '{obj.Properties[@"samaccountname"][0]}' : {e}");
                    }
                }
                if (args.XOR != null)
                {
                    try
                    {
                        foreach (var xor in args.XOR)
                        {
                            var PropertyName = xor.Key;
                            var PropertyXorValue = (int)xor.Value;
                            Logger.Write_Verbose($@"[Set-DomainObject] XORing '{PropertyName}' with '{PropertyXorValue}' for object '{obj.Properties[@"samaccountname"][0]}'");
                            var TypeName = Entry.Properties[PropertyName][0].GetType();

                            // UAC value references- https://support.microsoft.com/en-us/kb/305144
                            var PropertyValue = (int)Entry.Properties[PropertyName][0] ^ PropertyXorValue;
                            Entry.Properties[PropertyName][0] = PropertyValue;
                        }
                        Entry.CommitChanges();
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Set-DomainObject] Error XOR'ing properties for object '{obj.Properties[@"samaccountname"][0]}' : {e}");
                    }
                }
                if (args.Clear != null)
                {
                    try
                    {
                        foreach (var clear in args.Clear)
                        {
                            var PropertyName = clear;
                            Logger.Write_Verbose($@"[Set-DomainObject] Clearing '{PropertyName}' for object '{obj.Properties[@"samaccountname"][0]}'");
                            Entry.Properties[PropertyName].Clear();
                        }
                        Entry.CommitChanges();
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Set-DomainObject] Error clearing properties for object '{obj.Properties[@"samaccountname"][0]}' : {e}");
                    }
                }
            }
        }

    }
}
