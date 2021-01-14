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
    class GetDomainDNSRecord
    {
        private static string Get_Name(byte[] Raw)
        {
            int Length = Raw[0];
            int Segments = Raw[1];
            int Index = 2;
            string Name = "";

            while (Segments-- > 0)
            {
                int SegmentLength = Raw[Index++];
                while (SegmentLength-- > 0)
                {
                    Name += (char)Raw[Index++];
                }
                Name += ".";
            }
            return Name;
        }

        private static DNSRecord Convert_DNSRecord(byte[] DNSRecord)
        {
            // $RDataLen = [BitConverter]::ToUInt16($DNSRecord, 0)
            var RDataType = BitConverter.ToUInt16(DNSRecord, 2);
            var UpdatedAtSerial = BitConverter.ToUInt32(DNSRecord, 8);

            var TTLRaw = DNSRecord.Skip(12).Take(15 + 1 - 12);

            // reverse for big endian
            TTLRaw = TTLRaw.Reverse();
            var TTL = BitConverter.ToUInt32(TTLRaw.ToArray(), 0);

            var Age = BitConverter.ToUInt32(DNSRecord, 20);
            string TimeStamp = null;
            if (Age != 0)
            {
                TimeStamp = (new DateTime(1601, 1, 1, 0, 0, 0).AddHours(Age)).ToString();
            }
            else
            {
                TimeStamp = @"[static]";
            }

            var DNSRecordObject = new DNSRecord();
            string Data = null;

            if (RDataType == 1)
            {
                var IP = string.Format(@"{0}.{1}.{2}.{3}", DNSRecord[24], DNSRecord[25], DNSRecord[26], DNSRecord[27]);
                Data = IP;
                DNSRecordObject.RecordType = DnsRecordType.A;
            }

            else if (RDataType == 2)
            {
                var NSName = Get_Name(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                Data = NSName;
                DNSRecordObject.RecordType = DnsRecordType.NS;
            }

            else if (RDataType == 5)
            {
                var Alias = Get_Name(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                Data = Alias;
                DNSRecordObject.RecordType = DnsRecordType.CNAME;
            }

            else if (RDataType == 6)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.SOA;
            }

            else if (RDataType == 12)
            {
                var Ptr = Get_Name(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                Data = Ptr;
                DNSRecordObject.RecordType = DnsRecordType.PTR;
            }

            else if (RDataType == 13)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.HINFO;
            }

            else if (RDataType == 15)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.MX;
            }

            else if (RDataType == 16)
            {
                var TXT = "";
                int SegmentLength = DNSRecord[24];
                var Index = 25;

                while (SegmentLength-- > 0)
                {
                    TXT += (char)DNSRecord[Index++];
                }

                Data = TXT;
                DNSRecordObject.RecordType = DnsRecordType.TXT;
            }

            else if (RDataType == 28)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.AAAA;
            }

            else if (RDataType == 33)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.SRV;
            }

            else
            {
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.UNKNOWN;
            }

            DNSRecordObject.UpdatedAtSerial = UpdatedAtSerial;
            DNSRecordObject.TTL = TTL;
            DNSRecordObject.Age = Age;
            DNSRecordObject.TimeStamp = TimeStamp;
            DNSRecordObject.Data = Data;
            return DNSRecordObject;
        }

        public static IEnumerable<DNSRecord> Get_DomainDNSRecord(Args_Get_DomainDNSRecord args = null)
        {
            if (args == null) args = new Args_Get_DomainDNSRecord();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                LDAPFilter = @"(objectClass=dnsNode)",
                SearchBasePrefix = $@"DC={args.ZoneName},CN=MicrosoftDNS,DC=DomainDnsZones",
                Domain = args.Domain,
                Server = args.Server,
                Properties = args.Properties,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Credential = args.Credential
            };
            var DNSSearcher = GetDomainSearcher.Get_DomainSearcher(SearcherArguments);

            SearchResult[] Results = null;
            List<DNSRecord> Outs = null;
            if (DNSSearcher != null)
            {
                if (args.FindOne) { Results = new SearchResult[] { DNSSearcher.FindOne() }; }
                else
                {
                    var items = DNSSearcher.FindAll();
                    if (items != null)
                    {
                        Results = new SearchResult[items.Count];
                        items.CopyTo(Results, 0);
                    }
                }
                if (Results != null)
                {
                    foreach (var result in Results)
                    {
                        DNSRecord Out = null;
                        try
                        {
                            var ldapProperty = ConvertLDAPProperty.Convert_LDAPProperty(result.Properties);
                            Out = new DNSRecord
                            {
                                name = ldapProperty.name,
                                distinguishedname = ldapProperty.distinguishedname,
                                dnsrecord = ldapProperty.dnsrecord,
                                whencreated = ldapProperty.whencreated,
                                whenchanged = ldapProperty.whenchanged,
                                ZoneName = args.ZoneName
                            };

                            // convert the record and extract the properties
                            DNSRecord Record = null;
                            if (Out.dnsrecord is System.DirectoryServices.ResultPropertyValueCollection)
                            {
                                // TODO: handle multiple nested records properly?
                                Record = Convert_DNSRecord((Out.dnsrecord as System.DirectoryServices.ResultPropertyValueCollection)[0] as byte[]);
                            }
                            else
                            {
                                Record = Convert_DNSRecord(Out.dnsrecord as byte[]);
                            }

                            if (Record != null)
                            {
                                if (Record.RecordType != null)
                                    Out.RecordType = Record.RecordType;
                                else if (Record.UpdatedAtSerial != null)
                                    Out.UpdatedAtSerial = Record.UpdatedAtSerial;
                                else if (Record.TTL != null)
                                    Out.TTL = Record.TTL;
                                else if (Record.Age != null)
                                    Out.Age = Record.Age;
                                else if (Record.TimeStamp != null)
                                    Out.TimeStamp = Record.TimeStamp;
                                else if (Record.Data.IsNotNullOrEmpty())
                                    Out.Data = Record.Data;
                                else if (Record.ZoneName.IsNotNullOrEmpty())
                                    Out.ZoneName = Record.ZoneName;
                                else if (Record.name.IsNotNullOrEmpty())
                                    Out.name = Record.name;
                                else if (Record.distinguishedname.IsNotNullOrEmpty())
                                    Out.distinguishedname = Record.distinguishedname;
                                else if (Record.dnsrecord != null)
                                    Out.dnsrecord = Record.dnsrecord;
                                else if (Record.whencreated != null)
                                    Out.whencreated = Record.whencreated;
                                else if (Record.whenchanged != null)
                                    Out.whenchanged = Record.whenchanged;
                            }
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Warning($@"[Get-DomainDNSRecord] Error: {e}");
                        }
                        if (Outs == null) Outs = new List<DNSRecord>();
                        Outs.Add(Out);
                    }
                }
                DNSSearcher.Dispose();
            }
            return Outs;
        }

    }
}
