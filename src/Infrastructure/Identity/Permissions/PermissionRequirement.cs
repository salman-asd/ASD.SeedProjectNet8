using Microsoft.AspNetCore.Authorization;

namespace ASD.SeedProjectNet8.Infrastructure.Identity.Permissions;
public record PermissionRequirement(string Permission) : IAuthorizationRequirement;

