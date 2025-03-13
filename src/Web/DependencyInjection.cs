using Azure.Identity;
using ASD.SeedProjectNet8.Application.Common.Interfaces;
using ASD.SeedProjectNet8.Infrastructure.Data;
using ASD.SeedProjectNet8.Web.Services;
using Microsoft.AspNetCore.Mvc;
using ASD.SeedProjectNet8.Web.Middlewares;
using NSwag.Generation.Processors.Security;
using NSwag;


namespace Microsoft.Extensions.DependencyInjection;

public static class DependencyInjection
{
    public static IServiceCollection AddWebServices(this IServiceCollection services)
    {
        services.AddDatabaseDeveloperPageExceptionFilter();
        services.AddExceptionHandlers();

        services.AddScoped<IUser, CurrentUser>();

        services.AddHttpContextAccessor();

        services.AddHealthChecks()
            .AddDbContextCheck<ApplicationDbContext>();

        services.AddRazorPages();

        // Customise default API behaviour
        services.Configure<ApiBehaviorOptions>(options =>
            options.SuppressModelStateInvalidFilter = true);

        services.AddEndpointsApiExplorer();

        //services.AddOpenApiDocument((configure, sp) =>
        //{
        //    configure.Title = "ASD.SeedProjectNet8 API";

        //});

        services.AddOpenApiDocument((configure, sp) =>
        {
            configure.Title = "ASD.Onboard API";

            // Add the fluent validations schema processor
            //var fluentValidationSchemaProcessor =
            //    sp.CreateScope().ServiceProvider.GetRequiredService<FluentValidationSchemaProcessor>();

            // BUG: SchemaProcessors is missing in NSwag 14 (https://github.com/RicoSuter/NSwag/issues/4524#issuecomment-1811897079)
            // configure.SchemaProcessors.Add(fluentValidationSchemaProcessor);

            // Add JWT
            configure.AddSecurity("JWT", [], new OpenApiSecurityScheme
            {
                Type = OpenApiSecuritySchemeType.ApiKey,
                Name = "Authorization",
                In = OpenApiSecurityApiKeyLocation.Header,
                Description = "Type into the textbox: Bearer {your JWT token}."
            });

            configure.OperationProcessors.Add(new AspNetCoreOperationSecurityScopeProcessor("JWT"));
        });

        return services;
    }

    public static IServiceCollection AddKeyVaultIfConfigured(this IServiceCollection services, ConfigurationManager configuration)
    {
        var keyVaultUri = configuration["AZURE_KEY_VAULT_ENDPOINT"];
        if (!string.IsNullOrWhiteSpace(keyVaultUri))
        {
            configuration.AddAzureKeyVault(
                new Uri(keyVaultUri),
                new DefaultAzureCredential());
        }

        return services;
    }

    private static void AddExceptionHandlers(this IServiceCollection services)
    {
        services.AddExceptionHandler<CustomExceptionHandler>();
        services.AddExceptionHandler<GlobalExceptionHandlerMiddleware>();
        services.AddProblemDetails();
    }
}
