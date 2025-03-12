using Microsoft.IdentityModel.Tokens;

namespace ASD.SeedProjectNet8.Infrastructure.Identity.Services;

internal interface IAccessTokenValidator
{
    Task<TokenValidationResult> ValidateTokenAsync(string accessToken);
}
