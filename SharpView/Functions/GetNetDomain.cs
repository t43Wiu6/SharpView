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
    class GetNetDomain
    { 
        public static System.DirectoryServices.ActiveDirectory.Domain Get_NetDomain(Args_Get_Domain args = null)
        {
            return GetDomain.Get_Domain(args);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>

    }
}
