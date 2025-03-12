using ASD.SeedProjectNet8.Application.Common.Interfaces;
using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Interfaces;

namespace ASD.SeedProjectNet8.Application.Identity.Commands;

public record ChangePasswordCommand(
    string OldPassword,
    string NewPassword) : IRequest<Result>;

internal sealed class ChangePasswordCommandHandler(
    IAuthService authService,
    IUser user) : IRequestHandler<ChangePasswordCommand, Result>
{
    public async Task<Result> Handle(ChangePasswordCommand request, CancellationToken cancellationToken)
    {
        return await authService.ChangePasswordAsync(user.Id, request.OldPassword, request.NewPassword);
    }
}
