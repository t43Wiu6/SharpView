using System;
using SharpView.Arguments;
using SharpView.Returns;
using SharpView.Utils;

namespace SharpView.Functions
{ 
    class AddDomainGroupMember
    { 
        public static void Add_DomainGroupMember(Args_Add_DomainGroupMember args = null)
        {
            if (args == null) args = new Args_Add_DomainGroupMember();

            var ContextArguments = new Args_Get_PrincipalContext
            {
                Identity = args.Identity,
                Domain = args.Domain,
                Credential = args.Credential
            };
            var GroupContext = GetPrincipalContext.Get_PrincipalContext(ContextArguments);

            System.DirectoryServices.AccountManagement.GroupPrincipal Group = null;
            if (GroupContext != null)
            {
                try
                {
                    Group = System.DirectoryServices.AccountManagement.GroupPrincipal.FindByIdentity(GroupContext.Context, GroupContext.Identity);
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Add-DomainGroupMember] Error finding the group identity '{args.Identity}' : {e}");
                }
            }

            if (Group != null)
            {
                PrincipalContextEx UserContext = null;
                var UserIdentity = string.Empty;
                foreach (var Member in args.Members)
                {
                    if (Member.IsRegexMatch(@".+\\.+"))
                    {
                        ContextArguments.Identity = Member;
                        UserContext = GetPrincipalContext.Get_PrincipalContext(ContextArguments);
                        if (UserContext != null)
                        {
                            UserIdentity = UserContext.Identity;
                        }
                    }
                    else
                    {
                        UserContext = GroupContext;
                        UserIdentity = Member;
                    }
                    Logger.Write_Verbose($@"[Add-DomainGroupMember] Adding member '{Member}' to group '{args.Identity}'");
                    Group.Members.Add(System.DirectoryServices.AccountManagement.Principal.FindByIdentity(UserContext.Context, UserIdentity));
                    Group.Save();
                }
            }
        }

    }
}
