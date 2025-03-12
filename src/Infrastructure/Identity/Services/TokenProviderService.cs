using ASD.SeedProjectNet8.Infrastructure.Identity.Entities;
using ASD.SeedProjectNet8.Infrastructure.Identity.OptionsSetup;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ASD.SeedProjectNet8.Infrastructure.Identity.Services;

internal sealed class TokenProviderService(
    IOptionsSnapshot<JwtOptions> jwtOptions,
    UserManager<ApplicationUser> userManager)
    : ITokenProviderService
{
    private readonly JwtOptions _jwtOptions = jwtOptions.Value;

    public async Task<(string AccessToken, int ExpiresInMinutes)> GenerateAccessTokenAsync(ApplicationUser user)
    {
        var roles = await userManager.GetRolesAsync(user!);

        var userRolesAsClaims = roles.Select(r => new Claim(ClaimTypes.Role, r)).ToArray();

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user!.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user!.Id),
            //new Claim(JwtRegisteredClaimNames.Email, user.Email!),
            new Claim("username", user.UserName!),
        }
        .Union(userRolesAsClaims);

        var key = Encoding.UTF8.GetBytes(_jwtOptions.SecretKey);
        var symmetricSecurityKey = new SymmetricSecurityKey(key);
        var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

        var accessToken = new JwtSecurityToken(
             issuer: _jwtOptions.Issuer,
             audience: _jwtOptions.Audience,
             claims: claims,
             expires: DateTime.UtcNow.AddMinutes(_jwtOptions.DurationInMinutes),
             signingCredentials: signingCredentials
        );

        string tokenValue = new JwtSecurityTokenHandler().WriteToken(accessToken);

        return (tokenValue, _jwtOptions.DurationInMinutes);
    }

    public string GenerateRefreshToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }
}
