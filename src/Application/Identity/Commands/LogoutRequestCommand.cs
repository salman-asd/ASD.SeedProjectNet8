using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Interfaces;

namespace ASD.SeedProjectNet8.Application.Identity.Commands;
public sealed record LogoutRequestCommand(
    string RefreshToken)
    : IRequest<Result>;

internal sealed class LogoutRequestCommandHandler(IAuthService authService)
    : IRequestHandler<LogoutRequestCommand, Result>
{
    public async Task<Result> Handle(LogoutRequestCommand request, CancellationToken cancellationToken)
    {
        return await authService.LogoutAsync(request.RefreshToken, cancellationToken);
    }
}
