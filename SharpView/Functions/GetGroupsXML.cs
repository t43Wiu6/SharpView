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
    class GetGroupsXML
    { 
        public static IEnumerable<GroupsXML> Get_GroupsXML(Args_Get_GroupsXML args = null)
        {
            if (args == null) args = new Args_Get_GroupsXML();
            var MappedPaths = new Dictionary<string, bool>();
            var GroupsXMLs = new List<GroupsXML>();

            try
            {
                if (args.GroupsXMLPath.IsRegexMatch(@"\\\\.*\\.*") && args.Credential != null)
                {
                    var SysVolPath = $@"\\{new System.Uri(args.GroupsXMLPath).Host}\SYSVOL";
                    if (!MappedPaths[SysVolPath])
                    {
                        // map IPC$ to this computer if it's not already
                        AddRemoteConnection.Add_RemoteConnection(new Args_Add_RemoteConnection { Path = new[] { SysVolPath }, Credential = args.Credential });
                        MappedPaths[SysVolPath] = true;
                    }
                }

                XmlDocument GroupsXMLcontent = new XmlDocument();
                GroupsXMLcontent.Load(args.GroupsXMLPath);

                // process all group properties in the XML
                var nodes = GroupsXMLcontent.SelectNodes(@"/Groups/Group");
                foreach (XmlNode node in nodes)
                {
                    var GroupName = node["groupName"].InnerText;

                    // extract the localgroup sid for memberof
                    var GroupSID = node[@"groupSid"].InnerText;
                    if (GroupSID.IsNotNullOrEmpty())
                    {
                        if (GroupName.IsRegexMatch(@"Administrators"))
                        {
                            GroupSID = @"S-1-5-32-544";
                        }
                        else if (GroupName.IsRegexMatch(@"Remote Desktop"))
                        {
                            GroupSID = @"S-1-5-32-555";
                        }
                        else if (GroupName.IsRegexMatch(@"Guests"))
                        {
                            GroupSID = @"S-1-5-32-546";
                        }
                        else
                        {
                            if (args.Credential != null)
                            {
                                GroupSID = ConvertToSID.ConvertTo_SID(new Args_ConvertTo_SID { ObjectName = new[] { GroupName }, Credential = args.Credential }).FirstOrDefault();
                            }
                            else
                            {
                                GroupSID = ConvertToSID.ConvertTo_SID(new Args_ConvertTo_SID { ObjectName = new[] { GroupName } }).FirstOrDefault();
                            }
                        }
                    }

                    // extract out members added to this group
                    var Members = new List<string>();
                    foreach (XmlNode member in node["members"].SelectNodes("//Member"))
                    {
                        if (member["action"].InnerText.IsRegexMatch("ADD"))
                        {
                            if (member["sid"] != null) { Members.Add(member["sid"].InnerText); }
                            else { Members.Add(member["name"].InnerText); }
                        }

                        if (Members != null)
                        {
                            // extract out any/all filters...I hate you GPP
                            var Filters = new List<Filter>();

                            if (node.Attributes != null)
                            {
                                foreach (XmlAttribute filter in node.Attributes)
                                {
                                    Filters.Add(new Filter { Type = filter.LocalName, Value = filter.Name });
                                }
                            }
                            else
                            {
                                Filters = null;
                            }

                            var GroupsXML = new GroupsXML
                            {
                                GPOPath = args.GroupsXMLPath,
                                Filters = Filters,
                                GroupName = GroupName,
                                GroupSID = GroupSID,
                                GroupMemberOf = null,
                                GroupMembers = Members
                            };
                            GroupsXMLs.Add(GroupsXML);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logger.Write_Verbose($@"[Get-GroupsXML] Error parsing {args.GroupsXMLPath} : {e}");
            }
            // remove the SYSVOL mappings
            foreach (var key in MappedPaths.Keys)
            {
                RemoveRemoteConnection.Remove_RemoteConnection(new Args_Remove_RemoteConnection { Path = new[] { key } });
            }
            return GroupsXMLs;
        }

    }
}
