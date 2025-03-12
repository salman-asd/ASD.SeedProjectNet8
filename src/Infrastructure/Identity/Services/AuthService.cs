using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Infrastructure.Identity.OptionsSetup;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ASD.SeedProjectNet8.Application.Identity.Models;
using ASD.SeedProjectNet8.Application.Identity.Interfaces;

namespace ASD.SeedProjectNet8.Infrastructure.Identity.Services;

internal sealed class AuthService(
    UserManager<ApplicationUser> userManager,
    ITokenProviderService tokenProvider,
    IdentityDbContext dbContext,
    IOptionsSnapshot<JwtOptions> jwtOptions,
    ILogger<AuthService> logger,
    //IBackgroundJobService backgroundJobService,
    //IEmailService emailService,
    IConfiguration configuration,
    IHttpContextAccessor httpContext)
    : IAuthService
{
    private readonly JwtOptions _jwtOptions = jwtOptions.Value;

    public async Task<AuthenticatedResponse> LoginAsync(
        string username,
        string password,
        bool rememberMe = false,
        CancellationToken cancellation = default)
    {
        var user = await FindUserByUsernameOrEmail(username);

        if (user is null
            || !await userManager.CheckPasswordAsync(user, password))
        {
            logger.LogWarning("Invalid login attempt for user {Username}", username);
            throw new UnauthorizedAccessException("Invalid login attempt");
            //return Error.NotFound(nameof(user), ErrorMessages.WRONG_USERNAME_PASSWORD);
        }

        // Generate new tokens
        return await GenerateTokenResponseAsync(user, rememberMe, cancellation);
    }

    public async Task<AuthenticatedResponse> RefreshTokenAsync(
        string accessToken,
        string refreshToken,
        CancellationToken cancellation = default)
    {
        var existingRefreshToken = await dbContext.RefreshTokens
            .Include(x => x.ApplicationUser)
            .SingleOrDefaultAsync(x => x.Token == refreshToken, cancellation);

        if (existingRefreshToken is null
            || !existingRefreshToken.IsActive)
        {
            logger.LogWarning("Token refresh failed: Invalid or inactive refresh token");
            throw new UnauthorizedAccessException("Invalid or inactive refresh token");
        }

        // Get ClaimPrincipal from accessToken
        var claimsPrincipalResult = GetClaimsPrincipalFromToken(accessToken);

        var userId = claimsPrincipalResult?.FindFirstValue(ClaimTypes.NameIdentifier);

        // Ensure the refresh token belongs to the user
        if (existingRefreshToken.UserId != userId)
        {
            logger.LogWarning("Token refresh failed: Token does not belong to user");
            throw new UnauthorizedAccessException("Token does not belong to user");
            //return Error.Validation("Token", "Invalid refresh token");
        }

        var (newAccessToken, accessTokenExpiration) = await tokenProvider
            .GenerateAccessTokenAsync(existingRefreshToken.ApplicationUser);

        var newRefreshToken = await RotateRefreshToken(existingRefreshToken, cancellation);

        return new AuthenticatedResponse(
            newAccessToken,
            accessTokenExpiration,
            newRefreshToken.Token,
            newRefreshToken.Expires);
    }

    public async Task<Result> Logout(
        string userId,
        string accessToken,
        string refreshToken,
        CancellationToken cancellation = default)
    {
        // Get ClaimPrincipal from accessToken
        var claimsPrincipalResult = GetClaimsPrincipalFromToken(accessToken);

        // Get Identity UserId  from ClaimPrincipal
        var userIdFromAccessToken = claimsPrincipalResult?.FindFirstValue(ClaimTypes.NameIdentifier);

        var existingRefreshToken = await dbContext.RefreshTokens
            .SingleOrDefaultAsync(x => x.Token == refreshToken, cancellation);

        if (existingRefreshToken is not null)
        {
            existingRefreshToken.Revoked = DateTime.UtcNow;
            await dbContext.SaveChangesAsync(cancellation);
        }
        logger.LogInformation("User {UserId} logged out successfully", userId);

        return Result.Success();
    }

    public async Task<Result> ChangePasswordAsync(
         string userId,
         string currentPassword,
         string newPassword,
         CancellationToken cancellation = default)
    {
        var user = await userManager.FindByIdAsync(userId);

        if (user is null)
            throw new NotFoundException(nameof(user), userId);
            //return Error.Failure("User.Update", ErrorMessages.USER_NOT_FOUND);

        var identityResult = await userManager.ChangePasswordAsync(user, currentPassword, newPassword);

        if (!identityResult.Succeeded)
            return identityResult.ToApplicationResult();

        // Invalidate all refresh tokens
        await InvalidateUserAllRefreshTokensAsync(userId, cancellation);

        return identityResult.ToApplicationResult();
    }

    public async Task<Result> ForgotPasswordAsync(
            string email,
            CancellationToken cancellation = default)
    {
        var user = await userManager.FindByEmailAsync(email);

        //if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
        if (user is null)
            return Result.Success();

        // Generate password reset token
        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = Uri.EscapeDataString(token);

        var clientUrl = configuration.GetValue<string>("ClientUrl");

        // Create the reset link (frontend reset password route)
        var resetLink = $"{clientUrl}/auth/reset-password?token={encodedToken}&email={email}";

        // Enqueue email sending as a background job
        //backgroundJobService.EnqueueJob(() =>
        //    SendPasswordResetEmail(user, resetLink));

        return Result.Success();
    }

    public async Task<Result> ResetPasswordAsync(
        string email,
        string password,
        string token, CancellationToken cancellation = default)
    {
        var user = await userManager.FindByEmailAsync(email);

        if (user is null)
        {
            logger.LogWarning("Password reset requested for unknown user.");
            //return Error.Failure("User.ResetPassword", ErrorMessages.USER_NOT_FOUND);
            throw new UnauthorizedAccessException("Invalid user");
        }

        var result = await userManager.ResetPasswordAsync(user, token, password);

        if (!result.Succeeded)
            return result.ToApplicationResult();

        // Invalidate all refresh tokens
        await InvalidateUserAllRefreshTokensAsync(user.Id, cancellation);

        // Optionally, send a confirmation email
        //backgroundJobService.EnqueueJob(() =>
        //    PasswordResetConfirmationEmail(user));

        return Result.Success();
    }

    public async Task<Result> ConfirmEmailAsync(string email, Guid tokenId, CancellationToken cancellationToken = default)
    {
        //return await emailConfirmationService.ConfirmEmailAsync(email, tokenId, cancellationToken);
        return Result.Success();
    }


    private async Task<AuthenticatedResponse> GenerateTokenResponseAsync(
        ApplicationUser user,
        bool rememberMe = false,
        CancellationToken cancellationToken = default)
    {
        var (accessToken, accessTokenExpiration) = await tokenProvider.GenerateAccessTokenAsync(user);

        var refreshToken = new RefreshToken
        {
            Token = tokenProvider.GenerateRefreshToken(),
            Expires = rememberMe ? DateTime.UtcNow.AddDays(_jwtOptions.RememberMe) : DateTime.UtcNow.AddDays(_jwtOptions.RefreshTokenExpires),
            Created = DateTime.UtcNow,
            UserId = user.Id
        };

        dbContext.RefreshTokens.Add(refreshToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        return new AuthenticatedResponse(
            accessToken,
            accessTokenExpiration,
            refreshToken.Token,
            refreshToken.Expires);
    }

    private async Task<RefreshToken> RotateRefreshToken(
        RefreshToken existingToken,
        CancellationToken cancellationToken = default)
    {
        var newRefreshToken = new RefreshToken
        {
            Token = tokenProvider.GenerateRefreshToken(),
            Expires = DateTime.UtcNow.AddDays(_jwtOptions.RefreshTokenExpires),
            Created = DateTime.UtcNow,
            UserId = existingToken.UserId
        };
        existingToken.Revoked = DateTime.UtcNow;

        dbContext.RefreshTokens.Add(newRefreshToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        return newRefreshToken;
    }

    private async Task<ApplicationUser> FindUserByUsernameOrEmail(string identifier)
    {
        return await userManager.FindByEmailAsync(identifier)
               ?? await userManager.FindByNameAsync(identifier);
    }

    private async Task InvalidateUserAllRefreshTokensAsync(
        string userId,
        CancellationToken cancellationToken)
    {
        // Delete all refresh tokens for the user
        await dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);

        logger.LogInformation("Deleted all refresh tokens for user {UserId}", userId);
    }

    // Method to handle email sending (non-async signature)
    private void SendPasswordResetEmail(ApplicationUser user, string resetLink)
    {
        try
        {
            var templatePath = Path.Combine(
                Directory.GetCurrentDirectory(),
                "Templates",
                "ForgotPassword",
                 "ForgotPassword.cshtml");

            //emailService.SendTemplateEmailAsync(
            //    user.Email,
            //    "Password Reset",
            //    new { ReceiverName = user.FirstName, ResetLink = resetLink },
            //    templatePath
            //).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error sending password reset email to {Email}", user.Email);
        }
    }

    // Method to handle email sending (non-async signature)
    private void PasswordResetConfirmationEmail(ApplicationUser user)
    {
        try
        {
            var clientUrl = configuration.GetValue<string>("ClientUrl");

            var templatePath = Path.Combine(
                Directory.GetCurrentDirectory(),
                "Templates",
                "ForgotPassword",
                "ResetPasswordConfirmation.cshtml");

            //emailService.SendTemplateEmailAsync(
            //    user.Email,
            //    "Password Reset",
            //    new { ReceiverName = user.FirstName, SiteLink = clientUrl },
            //    templatePath
            //).GetAwaiter().GetResult();

        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error sending password reset confirmation email to {Email}", user.Email);
        }
    }

    private string? GetIpAddress()
    {
        return httpContext?.HttpContext?.Connection.RemoteIpAddress?.ToString();
    }

    private ClaimsPrincipal GetClaimsPrincipalFromToken(string accessToken)
    {

        try
        {
            TokenValidationParameters tokenValidationParameters = new()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, // it's false because already token lifetime validated
                ValidateIssuerSigningKey = true,
                ValidIssuer = _jwtOptions.Issuer,
                ValidAudience = _jwtOptions.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SecretKey)),
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken
                || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                //return Error.Validation("Token", ErrorMessages.INVALID_TOKEN);
                throw new UnauthorizedAccessException("Invalid token");
            }

            return principal;
        }
        catch
        {
            //return Error.Validation("Token", ErrorMessages.INVALID_TOKEN);
            throw new UnauthorizedAccessException("Invalid token");
        }
    }
}
