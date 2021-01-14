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
    class ConvertLDAPProperty
    {
        public static LDAPProperty Convert_LDAPProperty(System.DirectoryServices.ResultPropertyCollection Properties)
        {
            var ObjectProperties = new LDAPProperty();

            foreach (string propName in Properties.PropertyNames)
            {
                if (string.Compare(propName, @"adspath", StringComparison.OrdinalIgnoreCase) != 0)
                {
                    if (string.Compare(propName, @"objectsid", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"sidhistory", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        // convert all listed sids (i.e. if multiple are listed in sidHistory)
                        var values = new List<string>();
                        foreach (var property in Properties[propName])
                        {
                            var sid = new System.Security.Principal.SecurityIdentifier(property as byte[], 0);
                            values.Add(sid.Value);
                        }
                        if (string.Compare(propName, @"objectsid", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.objectsid = values.ToArray();
                        else
                            ObjectProperties.sidhistory = values.ToArray();
                    }
                    else if (string.Compare(propName, @"grouptype", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.grouptype = (GroupType)Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"samaccounttype", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.samaccounttype = (SamAccountType)Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"objectguid", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        // convert the GUID to a string
                        ObjectProperties.objectguid = new Guid(Properties[propName][0] as byte[]).ToString();
                    }
                    else if (string.Compare(propName, @"useraccountcontrol", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.useraccountcontrol = (UACEnumValue)Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"ntsecuritydescriptor", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        // $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                        var Descriptor = new System.Security.AccessControl.RawSecurityDescriptor(Properties[propName][0] as byte[], 0);
                        if (Descriptor.Owner != null)
                        {
                            ObjectProperties.Owner = Descriptor.Owner;
                        }
                        if (Descriptor.Group != null)
                        {
                            ObjectProperties.Group = Descriptor.Group;
                        }
                        if (Descriptor.DiscretionaryAcl != null)
                        {
                            ObjectProperties.DiscretionaryAcl = Descriptor.DiscretionaryAcl;
                        }
                        if (Descriptor.SystemAcl != null)
                        {
                            ObjectProperties.SystemAcl = Descriptor.SystemAcl;
                        }
                    }
                    else if (string.Compare(propName, @"accountexpires", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        if ((long)Properties[propName][0] >= DateTime.MaxValue.Ticks)
                        {
                            ObjectProperties.accountexpires = "NEVER";
                        }
                        else
                        {
                            ObjectProperties.accountexpires = DateTime.FromFileTime((long)Properties[propName][0]);
                        }
                    }
                    else if (string.Compare(propName, @"lastlogon", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"lastlogontimestamp", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"pwdlastset", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"lastlogoff", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"badPasswordTime", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"whencreated", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"whenchanged", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        DateTime dt;
                        // convert timestamps
                        if (Properties[propName][0] is System.MarshalByRefObject)
                        {
                            // if we have a System.__ComObject
                            var Temp = Properties[propName][0];
                            var High = (Int32)Temp.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, Temp, null);
                            var Low = (Int32)Temp.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, Temp, null);
                            dt = DateTime.FromFileTime(Int64.Parse(string.Format("0x{0:x8}{1:x8}", High, Low)));
                        }
                        if (Properties[propName][0] is System.DateTime)
                        {
                            dt = (DateTime)Properties[propName][0];
                        }
                        else
                        {
                            // otherwise just a string
                            dt = DateTime.FromFileTime((long)Properties[propName][0]);
                        }
                        if (string.Compare(propName, @"lastlogon", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.lastlogon = dt;
                        else if (string.Compare(propName, @"lastlogontimestamp", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.lastlogontimestamp = dt;
                        else if (string.Compare(propName, @"pwdlastset", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.pwdlastset = dt;
                        else if (string.Compare(propName, @"lastlogoff", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.lastlogoff = dt;
                        else if (string.Compare(propName, @"badPasswordTime", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.badPasswordTime = dt;
                        else if (string.Compare(propName, @"whencreated", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.whencreated = dt;
                        else if (string.Compare(propName, @"whenchanged", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.whenchanged = dt;
                    }
                    else if (string.Compare(propName, @"name", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.name = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"distinguishedname", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.distinguishedname = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"dnsrecord", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.dnsrecord = Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"samaccountname", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.samaccountname = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"member", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.member = Properties[propName].GetValues<string>().ToArray();
                    }
                    else if (string.Compare(propName, @"memberof", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.memberof = Properties[propName].GetValues<string>().ToArray();
                    }
                    else if (string.Compare(propName, @"cn", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.cn = Properties[propName].GetValues<string>().ToArray();
                    }
                    else if (string.Compare(propName, @"objectclass", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.objectclass = Properties[propName].GetValues<string>().ToArray();
                    }
                    else if (string.Compare(propName, @"managedby", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.managedby = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"siteobject", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.siteobject = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"ServicePrincipalName", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.ServicePrincipalName = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"dnshostname", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.dnshostname = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"gplink", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.gplink = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"gpoptions", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.gpoptions = (int)Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"displayname", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.displayname = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"path", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.path = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"siteobjectbl", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.siteobjectbl = Properties[propName][0] as string;
                    }
                    else if (Properties[propName][0] is System.MarshalByRefObject)
                    {
                        // try to convert misc com objects
                        var Prop = Properties[propName];
                        try
                        {
                            var Temp = Properties[propName][0];
                            var High = (Int32)Temp.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, Temp, null);
                            var Low = (Int32)Temp.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, Temp, null);
                            ObjectProperties.others.Add(propName, Int64.Parse(string.Format("0x{0:x8}{1:x8}", High, Low)));
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Convert-LDAPProperty] error: {e}");
                            ObjectProperties.others.Add(propName, Prop[0]);
                        }
                    }
                    else if (Properties[propName].Count == 1)
                    {
                        ObjectProperties.others.Add(propName, Properties[propName][0]);
                    }
                    else
                    {
                        ObjectProperties.others.Add(propName, Properties[propName]);
                    }
                }
            }
            return ObjectProperties;
        }

    }
}
