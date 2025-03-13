using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Models;

namespace ASD.SeedProjectNet8.Application.Identity.Interfaces;

public interface IAuthService
{
    Task<AuthenticatedResponse> LoginAsync(string username, string password, bool rememberMe = false, CancellationToken cancellation = default);
    Task<AuthenticatedResponse> RefreshTokenAsync(string refreshToken, string accessToken, CancellationToken cancellation = default);
    Task<Result> LogoutAsync(string refreshToken, CancellationToken cancellation = default);
    Task<Result> ChangePasswordAsync(string userId, string currentPassword, string newPassword, CancellationToken cancellation = default);
    Task<Result> ForgotPasswordAsync(string email, CancellationToken cancellation = default);
    Task<Result> ResetPasswordAsync(string email, string password, string token, CancellationToken cancellation = default);
    Task<Result> ConfirmEmailAsync(string email, Guid tokenId, CancellationToken cancellationToken = default);

}
