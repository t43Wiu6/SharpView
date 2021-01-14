using System;
using System.Collections.Generic;
using SharpView.Arguments;
using SharpView.Returns;
using SharpView.Enums;
using SharpView.Utils;

namespace SharpView.Functions
{ 
    class ResolveIPAddress
    { 
        public static IEnumerable<ComputerIPAddress> Resolve_IPAddress(Args_Resolve_IPAddress args = null)
        {
            if (args == null) args = new Args_Resolve_IPAddress();

            var addresses = new List<ComputerIPAddress>();
            foreach (var Computer in args.ComputerName)
            {
                try
                {
                    foreach (var address in System.Net.Dns.GetHostEntry(Computer).AddressList)
                    {
                        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            var Out = new ComputerIPAddress
                            {
                                ComputerName = Computer,
                                IPAddress = address.ToString()
                            };
                            addresses.Add(Out);
                        }
                    }
                }
                catch
                {
                    Logger.Write_Verbose(@"[Resolve-IPAddress] Could not resolve $Computer to an IP Address.");
                }
            }
            return addresses;
        }

    }
}
