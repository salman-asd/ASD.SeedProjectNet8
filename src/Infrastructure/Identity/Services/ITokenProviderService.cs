namespace ASD.SeedProjectNet8.Infrastructure.Identity.Services;

internal interface ITokenProviderService
{
    Task<(string AccessToken, int ExpiresInMinutes)> GenerateAccessTokenAsync(ApplicationUser user);
    string GenerateRefreshToken();

}
