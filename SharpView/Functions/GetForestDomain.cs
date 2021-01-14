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
    class GetForestDomain
    { 
        public static DomainCollection Get_ForestDomain(Args_Get_ForestDomain args = null)
        {
            if (args == null) args = new Args_Get_ForestDomain();

            var Arguments = new Args_Get_Forest
            {
                Forest = args.Forest,
                Credential = args.Credential
            };

            var ForestObject = GetForest.Get_Forest(Arguments);
            if (ForestObject != null)
            {
                return ForestObject.Forest?.Domains;
            }
            return null;
        }

    }
}
