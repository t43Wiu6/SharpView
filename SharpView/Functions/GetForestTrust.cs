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
    class GetForestTrust
    { 
        public static IEnumerable<IDomainTrust> Get_ForestTrust(Args_Get_Forest args = null)
        {
            if (args == null) args = new Args_Get_Forest();

            var FoundForest = GetForest.Get_Forest(args);

            if (FoundForest != null)
            {
                var items = FoundForest.Forest.GetAllTrustRelationships();
                var ForestTrusts = new List<IDomainTrust>();
                foreach (TrustRelationshipInformation item in items)
                {
                    ForestTrusts.Add(new NetDomainTrust
                    {
                        SourceName = item.SourceName,
                        TargetName = item.TargetName,
                        TrustDirection = item.TrustDirection,
                        TrustType = item.TrustType
                    });
                }
                return ForestTrusts;
            }
            return null;
        }

    }
}
