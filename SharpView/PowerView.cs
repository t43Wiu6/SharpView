using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using SharpView.Arguments;
using SharpView.Returns;
using SharpView.Enums;
using SharpView.Utils;
using SharpView.Interfaces;
using SharpView.Functions;

namespace SharpView
{
    public static class PowerView
    {
        public static void TestMethod()
        {
            Logger.Write_Warning("it works!");
        }

        public static System.DirectoryServices.ActiveDirectory.Domain Get_Domain(Args_Get_Domain args = null)
        {
            return GetDomain.Get_Domain(args);
        }
        public static System.DirectoryServices.ActiveDirectory.Domain Get_NetDomain(Args_Get_Domain args = null)
        {
            return GetNetDomain.Get_NetDomain(args);
        }
        public static IEnumerable<object> Get_DomainComputer(Args_Get_DomainComputer args = null)
        {
            return GetDomainComputer.Get_DomainComputer(args);
        }
        public static IEnumerable<object> Get_NetComputer(Args_Get_DomainComputer args = null)
        {
            return GetNetComputer.Get_NetComputer(args);
        }
        public static IEnumerable<object> Get_DomainController(Args_Get_DomainController args = null)
        {
            return GetDomainController.Get_DomainController(args);
        }
        public static IEnumerable<object> Get_NetDomainController(Args_Get_DomainController args = null)
        {
            return GetNetDomainController.Get_NetDomainController(args);
        }
        public static string[] Get_DomainFileServer(Args_Get_DomainFileServer args = null)
        {
            return GetDomainFileServer.Get_DomainFileServer(args);
        }
        public static string[] Get_NetFileServer(Args_Get_DomainFileServer args = null)
        {
            return GetNetFileServer.Get_NetFileServer(args);
        }
        public static IEnumerable<string> Convert_ADName(Args_Convert_ADName args)
        {
            return ConvertADName.Convert_ADName(args);
        }
        public static IEnumerable<object> Get_DomainObject(Args_Get_DomainObject args = null)
        {
            return GetDomainObject.Get_DomainObject(args);
        }
        public static IEnumerable<object> Get_ADObject(Args_Get_DomainObject args = null)
        {
            return GetADObject.Get_ADObject(args);
        }
        public static IEnumerable<object> Get_DomainUser(Args_Get_DomainUser args = null)
        {
            return GetDomainUser.Get_DomainUser(args);
        }
        public static IEnumerable<object> Get_NetUser(Args_Get_DomainUser args = null)
        {
            return GetNetUser.Get_NetUser(args);
        }
        public static IEnumerable<object> Get_LocalUser(Args_Get_DomainUser args = null)
        {
            return GetLocalUser.Get_LocalUser(args);
        }
        public static IEnumerable<object> Get_DomainGroup(Args_Get_DomainGroup args = null)
        {
            return GetDomainGroup.Get_DomainGroup(args);
        }
        public static IEnumerable<object> Get_NetGroup(Args_Get_DomainGroup args = null)
        {
            return GetNetGroup.Get_NetGroup(args);
        }
        public static IEnumerable<DFSShare> Get_DomainDFSShare(Args_Get_DomainDFSShare args = null)
        {
            return GetDomainDFSShare.Get_DomainDFSShare(args);
        }
        public static IEnumerable<DFSShare> Get_DFSshare(Args_Get_DomainDFSShare args = null)
        {
            return GetDFSshare.Get_DFSshare(args);
        }
        public static IEnumerable<DNSRecord> Get_DomainDNSRecord(Args_Get_DomainDNSRecord args = null)
        {
            return GetDomainDNSRecord.Get_DomainDNSRecord(args);
        }
        public static IEnumerable<DNSRecord> Get_DNSRecord(Args_Get_DomainDNSRecord args = null)
        {
            return GetDNSRecord.Get_DNSRecord(args);
        }
        public static IEnumerable<DNSZone> Get_DomainDNSZone(Args_Get_DomainDNSZone args = null)
        {
            return GetDomainDNSZone.Get_DomainDNSZone(args);
        }
        public static IEnumerable<DNSZone> Get_DNSZone(Args_Get_DomainDNSZone args = null)
        {
            return GetDNSZone.Get_DNSZone(args);
        }
        public static IEnumerable<ForeignGroupMember> Get_DomainForeignGroupMember(Args_Get_DomainForeignGroupMember args = null)
        {
            return GetDomainForeignGroupMember.Get_DomainForeignGroupMember(args);
        }
        public static IEnumerable<ForeignGroupMember> Find_ForeignGroup(Args_Get_DomainForeignGroupMember args = null)
        {
            return FindForeignGroup.Find_ForeignGroup(args);
        }
        public static IEnumerable<ForeignUser> Get_DomainForeignUser(Args_Get_DomainForeignUser args = null)
        {
            return GetDomainForeignUser.Get_DomainForeignUser(args);
        }
        public static IEnumerable<ForeignUser> Find_ForeignUser(Args_Get_DomainForeignUser args = null)
        {
            return FindForeignUser.Find_ForeignUser(args);
        }
        public static IEnumerable<string> ConvertFrom_SID(Args_ConvertFrom_SID args = null)
        {
            return ConvertFromSID.ConvertFrom_SID(args);
        }
        public static IEnumerable<string> Convert_SidToName(Args_ConvertFrom_SID args = null)
        {
            return ConvertSidToName.Convert_SidToName(args);
        }
        public static IEnumerable<GroupMember> Get_DomainGroupMember(Args_Get_DomainGroupMember args = null)
        {
            return GetDomainGroupMember.Get_DomainGroupMember(args);
        }
        public static IEnumerable<GroupMember> Get_NetGroupMember(Args_Get_DomainGroupMember args = null)
        {
            return GetNetGroupMember.Get_NetGroupMember(args);
        }
        public static IEnumerable<ManagedSecurityGroup> Get_DomainManagedSecurityGroup(Args_Get_DomainManagedSecurityGroup args = null)
        {
            return GetDomainManagedSecurityGroup.Get_DomainManagedSecurityGroup(args);
        }
        public static IEnumerable<ManagedSecurityGroup> Find_ManagedSecurityGroups(Args_Get_DomainManagedSecurityGroup args = null)
        {
            return FindManagedSecurityGroups.Find_ManagedSecurityGroups(args);
        }
        public static IEnumerable<object> Get_DomainOU(Args_Get_DomainOU args = null)
        {
            return GetDomainOU.Get_DomainOU(args);
        }
        public static IEnumerable<object> Get_NetOU(Args_Get_DomainOU args = null)
        {
            return GetNetOU.Get_NetOU(args);
        }
        public static string Get_DomainSID(Args_Get_DomainSID args = null)
        {
            return GetDomainSID.Get_DomainSID(args);
        }
        public static ForestEx Get_Forest(Args_Get_Forest args = null)
        {
            return GetForest.Get_Forest(args);
        }
        public static ForestEx Get_NetForest(Args_Get_Forest args = null)
        {
            return GetNetForest.Get_NetForest(args);
        }
        public static IEnumerable<IDomainTrust> Get_ForestTrust(Args_Get_Forest args = null)
        {
            return GetForestTrust.Get_ForestTrust(args);
        }
        public static System.DirectoryServices.ActiveDirectory.TrustRelationshipInformationCollection Get_NetForestTrust(Args_Get_Forest args = null)
        {
            return Get_NetForestTrust(args);
        }
        public static IEnumerable<IDomainTrust> Get_DomainTrust(Args_Get_DomainTrust args = null)
        {
            return GetDomainTrust.Get_DomainTrust(args);
        }
        public static IEnumerable<IDomainTrust> Get_NetDomainTrust(Args_Get_DomainTrust args = null)
        {
            return GetNetDomainTrust.Get_NetDomainTrust(args);
        }
        public static DomainCollection Get_ForestDomain(Args_Get_ForestDomain args = null)
        {
            return GetForestDomain.Get_ForestDomain(args);
        }
        public static DomainCollection Get_NetForestDomain(Args_Get_ForestDomain args = null)
        {
            return GetNetForestDomain.Get_NetForestDomain(args);
        }
        public static IEnumerable<object> Get_DomainSite(Args_Get_DomainSite args = null)
        {
            return GetDomainSite.Get_DomainSite(args);
        }
        public static IEnumerable<object> Get_NetSite(Args_Get_DomainSite args = null)
        {
            return GetNetSite.Get_NetSite(args);
        }
        public static IEnumerable<object> Get_DomainSubnet(Args_Get_DomainSubnet args = null)
        {
            return GetDomainSubnet.Get_DomainSubnet(args);
        }
        public static IEnumerable<object> Get_NetSubnet(Args_Get_DomainSubnet args = null)
        {
            return GetNetSubnet.Get_NetSubnet(args);
        }
        public static IEnumerable<IDomainTrust> Get_DomainTrustMapping(Args_Get_DomainTrustMapping args = null)
        {
            return GetDomainTrustMapping.Get_DomainTrustMapping(args);
        }
        public static IEnumerable<IDomainTrust> Invoke_MapDomainTrust(Args_Get_DomainTrustMapping args = null)
        {
            return InvokeMapDomainTrust.Invoke_MapDomainTrust(args);
        }
        public static IEnumerable<GlobalCatalog> Get_ForestGlobalCatalog(Args_Get_ForestGlobalCatalog args = null)
        {
            return GetForestGlobalCatalog.Get_ForestGlobalCatalog(args);
        }
        public static IEnumerable<GlobalCatalog> Get_NetForestCatalog(Args_Get_ForestGlobalCatalog args = null)
        {
            return GetNetForestCatalog.Get_NetForestCatalog(args);
        }
        public static IEnumerable<IWinEvent> Get_DomainUserEvent(Args_Get_DomainUserEvent args = null)
        {
            return GetDomainUserEvent.Get_DomainUserEvent(args);
        }
        public static IEnumerable<IWinEvent> Get_UserEvent(Args_Get_DomainUserEvent args = null)
        {
            return GetUserEvent.Get_UserEvent(args);
        }
        public static Dictionary<string, string> Get_DomainGUIDMap(Args_Get_DomainGUIDMap args = null)
        {
            return GetDomainGUIDMap.Get_DomainGUIDMap(args);
        }
        public static Dictionary<string, string> Get_GUIDMap(Args_Get_DomainGUIDMap args = null)
        {
            return GetGUIDMap.Get_GUIDMap(args);
        }
        public static IEnumerable<ComputerIPAddress> Resolve_IPAddress(Args_Resolve_IPAddress args = null)
        {
            return ResolveIPAddress.Resolve_IPAddress(args);
        }
        public static IEnumerable<ComputerIPAddress> Get_IPAddress(Args_Resolve_IPAddress args = null)
        {
            return GetIPAddress.Get_IPAddress(args);
        }
        public static IEnumerable<string> ConvertTo_SID(Args_ConvertTo_SID args = null)
        {
            return ConvertToSID.ConvertTo_SID(args);
        }
        public static IntPtr Invoke_UserImpersonation(Args_Invoke_UserImpersonation args = null)
        {
            return InvokeUserImpersonation.Invoke_UserImpersonation(args);
        }
        public static void Invoke_RevertToSelf(IntPtr TokenHandle)
        {
            InvokeRevertToSelf.Invoke_RevertToSelf(TokenHandle);
        }
        public static IEnumerable<ComputerSite> Get_NetComputerSiteName(Args_Get_NetComputerSiteName args = null)
        {
            return GetNetComputerSiteName.Get_NetComputerSiteName(args);
        }
        public static IEnumerable<ComputerSite> Get_SiteName(Args_Get_NetComputerSiteName args = null)
        {
            return GetSiteName.Get_SiteName(args);
        }
        public static IEnumerable<object> Get_DomainGPO(Args_Get_DomainGPO args = null)
        {
            return GetDomainGPO.Get_DomainGPO(args);
        }
        public static IEnumerable<object> Get_NetGPO(Args_Get_DomainGPO args = null)
        {
            return GetNetGPO.Get_NetGPO(args);
        }
        public static void Set_DomainObject(Args_Set_DomainObject args = null)
        {
            SetDomainObject.Set_DomainObject(args);
        }
        public static void Set_ADObject(Args_Set_DomainObject args = null)
        {
            SetADObject.Set_ADObject(args);
        }
        public static void Add_RemoteConnection(Args_Add_RemoteConnection args = null)
        {
            AddRemoteConnection.Add_RemoteConnection(args);
        }
        public static void Remove_RemoteConnection(Args_Remove_RemoteConnection args = null)
        {
            RemoveRemoteConnection.Remove_RemoteConnection(args);
        }
        public static IEnumerable<GroupsXML> Get_GroupsXML(Args_Get_GroupsXML args = null)
        {
            return GetGroupsXML.Get_GroupsXML(args);
        }
        public static IEnumerable<ACL> Get_DomainObjectAcl(Args_Get_DomainObjectAcl args = null)
        {
            return GetDomainObjectAcl.Get_DomainObjectAcl(args);
        }
        public static IEnumerable<ACL> Get_ObjectAcl(Args_Get_DomainObjectAcl args = null)
        {
            return GetObjectAcl.Get_ObjectAcl(args);
        }
        public static void Add_DomainObjectAcl(Args_Add_DomainObjectAcl args = null)
        {
            AddDomainObjectAcl.Add_DomainObjectAcl(args);
        }
        public static void Add_ObjectAcl(Args_Add_DomainObjectAcl args = null)
        {
            AddObjectAcl.Add_ObjectAcl(args);
        }
        public static void Remove_DomainObjectAcl(Args_Remove_DomainObjectAcl args = null)
        {
            RemoveDomainObjectAcl.Remove_DomainObjectAcl(args);
        }
        public static IEnumerable<RegLoggedOnUser> Get_RegLoggedOn(Args_Get_RegLoggedOn args = null)
        {
            return GetRegLoggedOn.Get_RegLoggedOn(args);
        }
        public static IEnumerable<RegLoggedOnUser> Get_LoggedOnLocal(Args_Get_RegLoggedOn args = null)
        {
            return GetLoggedOnLocal.Get_LoggedOnLocal(args);
        }
        public static IEnumerable<RDPSessionInfo> Get_NetRDPSession(Args_Get_NetRDPSession args = null)
        {
            return GetNetRDPSession.Get_NetRDPSession(args);
        }
        public static IEnumerable<AdminAccess> Test_AdminAccess(Args_Test_AdminAccess args = null)
        {
            return TestAdminAccess.Test_AdminAccess(args);
        }
        public static IEnumerable<AdminAccess> Invoke_CheckLocalAdminAccess(Args_Test_AdminAccess args = null)
        {
            return InvokeCheckLocalAdminAccess.Invoke_CheckLocalAdminAccess(args);
        }
        public static IEnumerable<UserProcess> Get_WMIProcess(Args_Get_WMIProcess args = null)
        {
            return GetWMIProcess.Get_WMIProcess(args);
        }
        public static IEnumerable<UserProcess> Get_NetProcess(Args_Get_WMIProcess args = null)
        {
            return GetNetProcess.Get_NetProcess(args);
        }
        public static IEnumerable<ProxySettings> Get_WMIRegProxy(Args_Get_WMIRegProxy args = null)
        {
            return GetWMIRegProxy.Get_WMIRegProxy(args);
        }
        public static IEnumerable<ProxySettings> Get_Proxy(Args_Get_WMIRegProxy args = null)
        {
            return GetProxy.Get_Proxy(args);
        }
        public static IEnumerable<LastLoggedOnUser> Get_WMIRegLastLoggedOn(Args_Get_WMIRegLastLoggedOn args = null)
        {
            return GetWMIRegLastLoggedOn.Get_WMIRegLastLoggedOn(args);
        }
        public static IEnumerable<LastLoggedOnUser> Get_LastLoggedOn(Args_Get_WMIRegLastLoggedOn args = null)
        {
            return GetLastLoggedOn.Get_LastLoggedOn(args);
        }
        public static IEnumerable<CachedRDPConnection> Get_WMIRegCachedRDPConnection(Args_Get_WMIRegCachedRDPConnection args = null)
        {
            return GetWMIRegCachedRDPConnection.Get_WMIRegCachedRDPConnection(args);
        }
        public static IEnumerable<CachedRDPConnection> Get_CachedRDPConnection(Args_Get_WMIRegCachedRDPConnection args = null)
        {
            return GetCachedRDPConnection.Get_CachedRDPConnection(args);
        }
        public static IEnumerable<RegMountedDrive> Get_WMIRegMountedDrive(Args_Get_WMIRegMountedDrive args = null)
        {
            return GetWMIRegMountedDrive.Get_WMIRegMountedDrive(args);
        }
        public static IEnumerable<RegMountedDrive> Get_RegistryMountedDrive(Args_Get_WMIRegMountedDrive args = null)
        {
            return GetRegistryMountedDrive.Get_RegistryMountedDrive(args);
        }
        public static IEnumerable<ACL> Find_InterestingDomainAcl(Args_Find_InterestingDomainAcl args = null)
        {
            return FindInterestingDomainAcl.Find_InterestingDomainAcl(args);
        }
        public static IEnumerable<ACL> Invoke_ACLScanner(Args_Find_InterestingDomainAcl args = null)
        {
            return InvokeACLScanner.Invoke_ACLScanner(args);
        }
        public static IEnumerable<ShareInfo> Get_NetShare(Args_Get_NetShare args = null)
        {
            return GetNetShare.Get_NetShare(args);
        }
        public static IEnumerable<LoggedOnUserInfo> Get_NetLoggedon(Args_Get_NetLoggedon args = null)
        {
            return GetNetLoggedon.Get_NetLoggedon(args);
        }
        public static IEnumerable<object> Get_NetLocalGroup(Args_Get_NetLocalGroup args = null)
        {
            return GetNetLocalGroup.Get_NetLocalGroup(args);
        }
        public static IEnumerable<object> Get_NetLocalGroupMember(Args_Get_NetLocalGroupMember args = null)
        {
            return GetNetLocalGroupMember.Get_NetLocalGroupMember(args);
        }
        public static IEnumerable<SessionInfo> Get_NetSession(Args_Get_NetSession args = null)
        {
            return GetNetSession.Get_NetSession(args);
        }
        public static IEnumerable<FileACL> Get_PathAcl(Args_Get_PathAcl args = null)
        {
            return GetPathAcl.Get_PathAcl(args);
        }
        public static System.Collections.Specialized.OrderedDictionary ConvertFrom_UACValue(Args_ConvertFrom_UACValue args = null)
        {
            return ConvertFromUACValue.ConvertFrom_UACValue(args);
        }
        public static PrincipalContextEx Get_PrincipalContext(Args_Get_PrincipalContext args = null)
        {
            return GetPrincipalContext.Get_PrincipalContext(args);
        }
        public static System.DirectoryServices.AccountManagement.GroupPrincipal New_DomainGroup(Args_New_DomainGroup args = null)
        {
            return NewDomainGroup.New_DomainGroup(args);
        }
        public static System.DirectoryServices.AccountManagement.UserPrincipal New_DomainUser(Args_New_DomainUser args = null)
        {
            return NewDomainUser.New_DomainUser(args);
        }
        public static void Add_DomainGroupMember(Args_Add_DomainGroupMember args = null)
        {
            AddDomainGroupMember.Add_DomainGroupMember(args);
        }
        public static void Set_DomainUserPassword(Args_Set_DomainUserPassword args = null)
        {
            SetDomainUserPassword.Set_DomainUserPassword(args);
        }
        public static void Export_PowerViewCSV(Args_Export_PowerViewCSV args = null)
        {
            ExportPowerViewCSV.Export_PowerViewCSV(args);
        }
        public static IEnumerable<string> Find_LocalAdminAccess(Args_Find_LocalAdminAccess args = null)
        {
            return FindLocalAdminAccess.Find_LocalAdminAccess(args);
        }
        public static IEnumerable<object> Find_DomainLocalGroupMember(Args_Find_DomainLocalGroupMember args = null)
        {
            return FindDomainLocalGroupMember.Find_DomainLocalGroupMember(args);
        }
        public static IEnumerable<ShareInfo> Find_DomainShare(Args_Find_DomainShare args = null)
        {
            return FindDomainShare.Find_DomainShare(args);
        }
        public static IEnumerable<object> Find_DomainUserEvent(Args_Find_DomainUserEvent args = null)
        {
            return FindDomainUserEvent.Find_DomainUserEvent(args);
        }
        public static IEnumerable<UserProcess> Find_DomainProcess(Args_Find_DomainProcess args = null)
        {
            return FindDomainProcess.Find_DomainProcess(args);
        }
        public static IEnumerable<UserLocation> Find_DomainUserLocation(Args_Find_DomainUserLocation args = null)
        {
            return FindDomainUserLocation.Find_DomainUserLocation(args);
        }
        public static IEnumerable<FoundFile> Find_InterestingFile(Args_Find_InterestingFile args = null)
        {
            return FindInterestingFile.Find_InterestingFile(args);
        }
        public static IEnumerable<FoundFile> Find_InterestingDomainShareFile(Args_Find_InterestingDomainShareFile args = null)
        {
            return FindInterestingDomainShareFile.Find_InterestingDomainShareFile(args);
        }
        public static IEnumerable<PropertyOutlier> Find_DomainObjectPropertyOutlier(Args_Find_DomainObjectPropertyOutlier args = null)
        {
            return FindDomainObjectPropertyOutlier.Find_DomainObjectPropertyOutlier(args);
        }

    }
}
