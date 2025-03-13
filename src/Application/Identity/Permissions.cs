namespace ASD.SeedProjectNet8.Application.Identity;

public static class Permissions
{
    // These will generate all constant property value of particular module like Faculties
    public static List<string> GetPermissionsByfeature(string feature)
    {
        return new List<string>
            {
                 $"Permissions.{feature}.Create",
                 $"Permissions.{feature}.View",
                 $"Permissions.{feature}.Edit",
                 $"Permissions.{feature}.Delete"
            };
    }

    public static List<string> GetPermissionsByfeatures(List<string> features)
    {
        List<string> permissions = [];
        foreach (string feature in features)
        {
            permissions.AddRange(new List<string>
            {
                 $"Permissions.{feature}.Create",
                 $"Permissions.{feature}.View",
                 $"Permissions.{feature}.Edit",
                 $"Permissions.{feature}.Delete"
            });
        }
        return permissions;
    }

    /// <summary>
    /// These will generate list of modules name (string) like ApplicationUsers, IdentityRoles
    /// </summary>
    /// <returns>List<string></returns>
    public static List<string> GetAllNestedModule(Type type)
    {
        Type[] nestedTypes = type.GetNestedTypes();
        List<string> result = [];
        foreach (var nestedType in nestedTypes)
        {
            result.Add(nestedType.Name);
        }
        return result;
    }

    /// <summary>
    /// These will generate list of modules type (Type) like ApplicationUsers, IdentityRoles
    /// </summary>
    /// <returns>Type[]</returns>
    public static Type[] GetAllNestedModuleType(Type type)
    {
        Type[] nestedTypes = type.GetNestedTypes();
        return nestedTypes;
    }

    #region Admin

    public static class Admin
    {
        public static class ApplicationUsers
        {
            public const string View = "Permissions.ApplicationUsers.View";
            public const string Create = "Permissions.ApplicationUsers.Create";
            public const string Edit = "Permissions.ApplicationUsers.Edit";
            public const string Delete = "Permissions.ApplicationUsers.Delete";
        }
        public static class IdentityRoles
        {
            public const string View = "Permissions.IdentityRoles.View";
            public const string Create = "Permissions.IdentityRoles.Create";
            public const string Edit = "Permissions.IdentityRoles.Edit";
            public const string Delete = "Permissions.IdentityRoles.Delete";
        }

        public static class ManageUserRoles
        {
            public const string View = "Permissions.ManageUserRoles.View";
            public const string Create = "Permissions.ManageUserRoles.Create";
            public const string Edit = "Permissions.ManageUserRoles.Edit";
            public const string Delete = "Permissions.ManageUserRoles.Delete";
        }

        public static class ManageRoleClaims
        {
            public const string View = "Permissions.ManageRoleClaims.View";
            public const string Create = "Permissions.ManageRoleClaims.Create";
            public const string Edit = "Permissions.ManageRoleClaims.Edit";
            public const string Delete = "Permissions.ManageRoleClaims.Delete";
        }
    }

    #endregion

    #region Todo

    public static class CommonSetup
    {
        public static class TodoItems
        {
            public const string View = "Permissions.TodoItems.View";
            public const string Create = "Permissions.TodoItems.Create";
            public const string Edit = "Permissions.TodoItems.Edit";
            public const string Delete = "Permissions.TodoItems.Delete";
        }

        public static class TodoLists
        {
            public const string View = "Permissions.TodoLists.View";
            public const string Create = "Permissions.TodoLists.Create";
            public const string Edit = "Permissions.TodoLists.Edit";
            public const string Delete = "Permissions.TodoLists.Delete";
        }

    }


    #endregion

}
