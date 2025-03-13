using ASD.SeedProjectNet8.Application.Common.Interfaces;
using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Interfaces;

namespace ASD.SeedProjectNet8.Application.Identity.Commands;

public record ResetPasswordCommand(
    string Email,
    string Token,
    string NewPassword) : IRequest<Result>;

internal sealed class ResetPasswordCommandHandler(IAuthService authService, IUser user)
    : IRequestHandler<ResetPasswordCommand, Result>
{
    public async Task<Result> Handle(ResetPasswordCommand request, CancellationToken cancellationToken)
    {
        var userinfo = user.Id;
        return await authService.ResetPasswordAsync(request.Email, request.Token, request.NewPassword);
    }
}
