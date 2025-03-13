using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Exceptions;
using ASD.SeedProjectNet8.Application.Identity.Interfaces;
using ASD.SeedProjectNet8.Application.Identity.Models;
using ASD.SeedProjectNet8.Infrastructure.Identity.Entities;
using ASD.SeedProjectNet8.Infrastructure.Identity.Extensions;
using ASD.SeedProjectNet8.Infrastructure.Identity.OptionsSetup;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

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

        if (user is null)
        {
            logger.LogWarning("Login attempt for non-existent user {Username}", username);
            throw new InvalidCredentialsException();
        }

        // Check if user is locked out
        if (await userManager.IsLockedOutAsync(user))
        {
            logger.LogWarning("Login attempt for locked out user {Username}", username);
            throw new UserLockedOutException();
        }

        // Verify password
        if (!await userManager.CheckPasswordAsync(user, password))
        {
            logger.LogWarning("Invalid password for user {Username}", username);

            // Update failed attempts counter
            await userManager.AccessFailedAsync(user);
            throw new InvalidCredentialsException();
        }

        // Check if email is confirmed (if required)
        if (userManager.Options.SignIn.RequireConfirmedEmail && !user.EmailConfirmed)
        {
            logger.LogWarning("Login attempt with unconfirmed email for user {Username}", username);
            throw new EmailConfirmationException();
        }

        // Reset lockout counters on successful login
        await userManager.ResetAccessFailedCountAsync(user);

        // Generate new tokens
        return await GenerateTokenResponseAsync(user, rememberMe, cancellation);
    }

    public async Task<AuthenticatedResponse> RefreshTokenAsync(
        string refreshToken,
        string accessToken,
        CancellationToken cancellation = default)
    {
        var existingRefreshToken = await dbContext.RefreshTokens
            .Include(x => x.ApplicationUser)
            .SingleOrDefaultAsync(x => x.Token == refreshToken, cancellation);

        if (existingRefreshToken is null)
        {
            logger.LogWarning("Token refresh failed: Refresh token not found");
            throw new RefreshTokenException();
        }

        if (!existingRefreshToken.IsActive)
        {
            logger.LogWarning("Token refresh failed: Refresh token is not active");
            throw new RefreshTokenException();
        }

        try
        {
            ValidateRefreshTokenOwnership(accessToken, existingRefreshToken.UserId);
        }
        catch
        {
            // If validation fails, invalidate the token
            existingRefreshToken.Revoked = DateTime.UtcNow;
            await dbContext.SaveChangesAsync(cancellation);
            throw;
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

    public async Task<Result> LogoutAsync(
        string refreshToken,
        CancellationToken cancellation = default)
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            return Result.Success();
        }

        var existingRefreshToken = await dbContext.RefreshTokens
            .SingleOrDefaultAsync(x => x.Token == refreshToken, cancellation);

        if (existingRefreshToken is not null)
        {
            existingRefreshToken.Revoked = DateTime.UtcNow;
            await dbContext.SaveChangesAsync(cancellation);
            logger.LogInformation("User {UserId} logged out successfully", existingRefreshToken.UserId);
        }

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
            throw new NotFoundException(nameof(ApplicationUser), userId);

        // Validate current password
        if (!await userManager.CheckPasswordAsync(user, currentPassword))
        {
            return Result.Failure(["Current password is incorrect"]);
        }

        var identityResult = await userManager.ChangePasswordAsync(user, currentPassword, newPassword);

        if (!identityResult.Succeeded)
            return identityResult.ToApplicationResult();

        // Invalidate all refresh tokens
        await InvalidateUserAllRefreshTokensAsync(userId, cancellation);

        return Result.Success();
    }

    public async Task<Result> ForgotPasswordAsync(
            string email,
            CancellationToken cancellation = default)
    {
        var user = await userManager.FindByEmailAsync(email);


        // Always return success to avoid leaking information about registered users
        if (user is null || !user.EmailConfirmed)
            return Result.Success();

        //if (user == null || !(await userManager.IsEmailConfirmedAsync(user)))
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
            logger.LogWarning("Password reset requested for unknown email: {Email}", email);
            throw new NotFoundException("User", email);
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

        // Optionally limit the number of active refresh tokens per user
        await EnforceRefreshTokenLimitPerUserAsync(user.Id, 5, cancellationToken);

        dbContext.RefreshTokens.Add(refreshToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation("User {UserId} authenticated successfully", user.Id);

        return new AuthenticatedResponse(
            accessToken,
            accessTokenExpiration,
            refreshToken.Token,
            refreshToken.Expires);
    }

    private async Task EnforceRefreshTokenLimitPerUserAsync(
        string userId,
        int maxActiveTokens,
        CancellationToken cancellationToken)
    {
        // Get all active tokens for the user
        var activeTokens = await dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId && rt.Revoked == null)
            .OrderByDescending(rt => rt.Created)
            .ToListAsync(cancellationToken);

        // If the user has more active tokens than allowed, revoke the oldest ones
        if (activeTokens.Count >= maxActiveTokens)
        {
            var tokensToRevoke = activeTokens.Skip(maxActiveTokens - 1).ToList();
            foreach (var token in tokensToRevoke)
            {
                token.Revoked = DateTime.UtcNow;
            }
            await dbContext.SaveChangesAsync(cancellationToken);
            logger.LogInformation("Revoked {Count} old refresh tokens for user {UserId}", tokensToRevoke.Count, userId);
        }
    }


    private async Task<RefreshToken> RotateRefreshToken(
        RefreshToken existingToken,
        CancellationToken cancellationToken = default)
    {
        // Revoke the existing token
        existingToken.Revoked = DateTime.UtcNow;

        // Create a new token that expires at the same time as the original would have
        var newRefreshToken = new RefreshToken
        {
            Token = tokenProvider.GenerateRefreshToken(),
            //Expires = DateTime.UtcNow.AddDays(_jwtOptions.RefreshTokenExpires),
            Expires = existingToken.Expires, // Maintain the original expiration time
            Created = DateTime.UtcNow,
            UserId = existingToken.UserId
        };

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
        // Find all active refresh tokens for the user
        var activeTokens = await dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId && rt.IsActive)
            .ExecuteUpdateAsync(token => token
                .SetProperty(x => x.Revoked, DateTime.UtcNow)
            );
        logger.LogInformation("Revoked all refresh tokens for user {UserId}", userId);
    }

    private void ValidateRefreshTokenOwnership(
           string accessToken,
           string refreshUserId)
    {
        ClaimsPrincipal claimsPrincipal;

        try
        {
            claimsPrincipal = GetClaimsPrincipalFromToken(accessToken);
        }
        catch
        {
            logger.LogWarning("Token refresh failed: Invalid access token");
            throw new InvalidTokenException();
        }

        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);

        // Ensure the refresh token belongs to the user
        if (refreshUserId != userId)
        {
            logger.LogWarning("Token refresh failed: Token does not belong to user");
            throw new RefreshTokenException();
        }
    }



    private ClaimsPrincipal GetClaimsPrincipalFromToken(string accessToken)
    {
        try
        {
            TokenValidationParameters tokenValidationParameters = new()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, // Don't validate lifetime as token might be expired
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
                throw new InvalidTokenException();
            }

            return principal;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Token validation failed");
            throw new InvalidTokenException();
        }
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
}
