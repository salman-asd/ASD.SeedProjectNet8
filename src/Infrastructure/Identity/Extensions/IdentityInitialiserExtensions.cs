using System.Security.Claims;
using ASD.SeedProjectNet8.Domain.Constants;
using ASD.SeedProjectNet8.Infrastructure.Identity.Entities;
using ASD.SeedProjectNet8.Infrastructure.Identity.Permissions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PermissionConstant = ASD.SeedProjectNet8.Application.Identity.Permissions;


namespace ASD.SeedProjectNet8.Infrastructure.Identity.Extensions;

public static class IdentityInitialiserExtensions
{
    public static async Task IdentityInitialiseDatabaseAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();

        var identityInitialiser = scope.ServiceProvider.GetRequiredService<IdentityDbContextInitialiser>();

        await identityInitialiser.InitialiseAsync();

        await identityInitialiser.SeedAsync();
    }
}

internal sealed class IdentityDbContextInitialiser(
        ILogger<IdentityDbContextInitialiser> logger,
        IdentityDbContext context,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager)
{
    public async Task InitialiseAsync()
    {
        try
        {
            if (!await context.Users.AsNoTracking().AnyAsync())
                await context.Database.MigrateAsync();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while initialising the database.");
            throw;
        }
    }

    public async Task SeedAsync()
    {
        try
        {
            //if (!await context.Users.AsNoTracking().AnyAsync())
                await SeedDefaultIdentityAsync();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while seeding the database.");
            throw;
        }
    }

    private async Task SeedDefaultIdentityAsync()
    {
        // Default roles
        var administratorRole = new IdentityRole(Roles.Administrator);

        if (roleManager.Roles.All(r => r.Name != administratorRole.Name))
        {
            await roleManager.CreateAsync(administratorRole);
        }

        var basicRole = new IdentityRole(Roles.Basic);

        if (roleManager.Roles.All(r => r.Name != basicRole.Name))
        {
            await roleManager.CreateAsync(basicRole);
        }

        // Get Permission
        var features = PermissionConstant.GetAllNestedModule(typeof(PermissionConstant.Admin));
        features.AddRange(PermissionConstant.GetAllNestedModule(typeof(PermissionConstant.CommonSetup)));

        var permissions = PermissionConstant.GetPermissionsByfeatures(features);

        // Default Permissions
        foreach (var permission in permissions)
        {
            // Check if the permission already exists for the role
            var existingClaims = await roleManager.GetClaimsAsync(administratorRole);
            var permissionExists = existingClaims.Any(c => c.Type == CustomClaimTypes.Permission && c.Value == permission);

            // If the permission does not exist, add it
            if (!permissionExists)
            {
                await roleManager.AddClaimAsync(administratorRole, new Claim(CustomClaimTypes.Permission, permission));
            }
        }

        // Default users
        var administrator = new ApplicationUser { UserName = "administrator@localhost", Email = "administrator@localhost" };

        if (userManager.Users.All(u => u.UserName != administrator.UserName))
        {
            await userManager.CreateAsync(administrator, "Salman@123");
            if (!string.IsNullOrWhiteSpace(administratorRole.Name))
            {
                await userManager.AddToRolesAsync(administrator, [administratorRole.Name]);
            }
            if (!string.IsNullOrWhiteSpace(basicRole.Name))
            {
                await userManager.AddToRolesAsync(administrator, [basicRole.Name]);
            }

        }
    }
}

