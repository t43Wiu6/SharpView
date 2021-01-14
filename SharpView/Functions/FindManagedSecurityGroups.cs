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
    class FindManagedSecurityGroups
    { 
        public static IEnumerable<ManagedSecurityGroup> Find_ManagedSecurityGroups(Args_Get_DomainManagedSecurityGroup args = null)
        {
            return GetDomainManagedSecurityGroup.Get_DomainManagedSecurityGroup(args);
        }

    }
}
