using System;
using System.Collections.Generic;
using SharpView.Arguments;
using SharpView.Returns;
using SharpView.Enums;
using SharpView.Utils;
using System.Linq;

namespace SharpView.Functions
{ 
    class ConvertToSID
    { 
        public static IEnumerable<string> ConvertTo_SID(Args_ConvertTo_SID args = null)
        {
            if (args == null) args = new Args_ConvertTo_SID();

            var DomainSearcherArguments = new Args_Get_DomainObject
            {
                Domain = args.Domain,
                Server = args.Server,
                Credential = args.Credential
            };

            var SIDs = new List<string>();
            foreach (var item in args.ObjectName)
            {
                var name = item.Replace(@"/", @"\");

                if (args.Credential != null)
                {
                    var DN = ConvertADName.Convert_ADName(new Args_Convert_ADName
                    {
                        Identity = new[] { name },
                        OutputType = ADSNameType.DN,
                        Domain = DomainSearcherArguments.Domain,
                        Server = DomainSearcherArguments.Server,
                        Credential = DomainSearcherArguments.Credential
                    });


                    if (DN != null)
                    {
                        var UserDomain = DN.First().Substring(DN.First().IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                        var UserName = DN.First().Split(',')[0].Split('=')[1];

                        DomainSearcherArguments.Identity = new[] { UserName };
                        DomainSearcherArguments.Domain = UserDomain;
                        DomainSearcherArguments.Properties = new[] { @"objectsid" };
                        var obj = GetDomainObject.Get_DomainObject(DomainSearcherArguments);
                        foreach (LDAPProperty ldapProperty in obj)
                        {
                            SIDs.AddRange(ldapProperty.objectsid);
                        }
                    }
                }
                else
                {
                    try
                    {
                        if (name.Contains(@"\"))
                        {
                            args.Domain = name.Split('\\')[0];
                            name = name.Split('\\')[1];
                        }
                        else if (args.Domain.IsNullOrEmpty())
                        {
                            args.Domain = GetDomain.Get_Domain().Name;
                        }

                        var obj = new System.Security.Principal.NTAccount(args.Domain, name);
                        SIDs.Add(obj.Translate(typeof(System.Security.Principal.SecurityIdentifier)).Value);
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[ConvertTo-SID] Error converting {args.Domain}\{name} : {e}");
                    }
                }
            }
            return SIDs;
        }

    }
}
