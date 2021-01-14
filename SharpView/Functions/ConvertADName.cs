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
    class ConvertADName
    { 
        public static IEnumerable<string> Convert_ADName(Args_Convert_ADName args)
        {
            ADSNameType ADSInitType;
            string InitName;
            // https://msdn.microsoft.com/en-us/library/aa772266%28v=vs.85%29.aspx
            if (args.Server.IsNotNullOrEmpty())
            {
                ADSInitType = ADSNameType.Canonical;
                InitName = args.Server;
            }
            else if (args.Domain.IsNotNullOrEmpty())
            {
                ADSInitType = ADSNameType.DN;
                InitName = args.Domain;
            }
            else if (args.Credential != null)
            {
                ADSInitType = ADSNameType.DN;
                InitName = args.Credential.Domain;
            }
            else
            {
                // if no domain or server is specified, default to GC initialization
                ADSInitType = ADSNameType.NT4;
                InitName = null;
            }

            var Names = new List<string>();
            ADSNameType ADSOutputType;
            if (args.Identity != null)
            {
                foreach (var TargetIdentity in args.Identity)
                {
                    if (args.OutputType == null)
                    {
                        if (new Regex(@"^[A-Za-z]+\\[A-Za-z ]+").Match(TargetIdentity).Success)
                        {
                            ADSOutputType = ADSNameType.DomainSimple;
                        }
                        else
                        {
                            ADSOutputType = ADSNameType.NT4;
                        }
                    }
                    else
                    {
                        ADSOutputType = args.OutputType.Value;
                    }
                    var Translate = new ActiveDs.NameTranslate();

                    if (args.Credential != null)
                    {
                        try
                        {
                            Translate.InitEx((int)ADSInitType, InitName, args.Credential.UserName, args.Credential.Domain, args.Credential.Password);
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Convert-ADName] Error initializing translation for '{args.Identity}' using alternate credentials : {e}");
                        }
                    }
                    else
                    {
                        try
                        {
                            Translate.Init((int)ADSInitType, InitName);
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Convert-ADName] Error initializing translation for '{args.Identity}' : {e}");
                        }
                    }

                    // always chase all referrals
                    Translate.ChaseReferral = 0x60;

                    try
                    {
                        // 8 = Unknown name type -> let the server do the work for us
                        Translate.Set((int)ADSNameType.Unknown, TargetIdentity);
                        Names.Add(Translate.Get((int)ADSOutputType));
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Convert-ADName] Error translating '{TargetIdentity}' : {e})");
                    }
                }
            }

            return Names;
        }

        /// <summary>
        /// 
        /// </summary>

    }
}
