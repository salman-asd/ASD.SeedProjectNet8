namespace ASD.SeedProjectNet8.Application.Identity.Models;

public sealed record AuthenticatedResponse(
    string AccessToken,
    int ExpiresInMinutes,
    string RefreshToken,
    DateTimeOffset RefreshTokenExpiresOn);
