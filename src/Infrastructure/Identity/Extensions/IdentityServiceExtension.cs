using ASD.SeedProjectNet8.Application.Common.Interfaces;
using ASD.SeedProjectNet8.Domain.Constants;
using ASD.SeedProjectNet8.Infrastructure.Identity.OptionsSetup;
using ASD.SeedProjectNet8.Infrastructure.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using ASD.SeedProjectNet8.Application.Identity.Interfaces;
using ASD.SeedProjectNet8.Infrastructure.Identity.Entities;

namespace ASD.SeedProjectNet8.Infrastructure.Identity.Extensions;

internal static class IdentityServiceExtension
{
    public static IServiceCollection AddIdentityService(this IServiceCollection services, IConfiguration configuration)
    {
        var identityConString = configuration.GetConnectionString("IdentityConnection");

        Guard.Against.Null(identityConString, message: $"Connection string 'IdentityConnection' not found.");

        services.AddDbContext<IdentityDbContext>(options => options.UseSqlServer(identityConString));

        services.AddIdentityCore<ApplicationUser>()
        .AddRoles<IdentityRole>()
        .AddEntityFrameworkStores<IdentityDbContext>()
        .AddApiEndpoints();

        // Configure reset token lifespan here
        services.Configure<DataProtectionTokenProviderOptions>(options =>
        {
            options.TokenLifespan = TimeSpan.FromMinutes(2);
        });

        services.AddScoped<IdentityDbContextInitialiser>();
        services.AddScoped<IIdentityService, IdentityService>();
        services.AddTransient<ICustomAuthorizationService, CustomAuthorizationService>();
        //services.AddTransient<IIdentityRoleService, IdentityRoleService>();
        services.AddTransient<IAuthService, AuthService>();
        services.AddTransient<ITokenProviderService, TokenProviderService>();

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer();

        services.ConfigureOptions<JwtOptionsSetup>();
        services.ConfigureOptions<JwtBearerOptionsSetup>();

        services.AddAuthorizationBuilder()
            .AddPolicy(Policies.CanPurge, policy => policy.RequireRole(Roles.Administrator));

        //services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>(); // Handles dynamic permission checks
        // For dynamically create policy if not exist
        //services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>(); // Dynamically provides policies

        return services;
    }
}
