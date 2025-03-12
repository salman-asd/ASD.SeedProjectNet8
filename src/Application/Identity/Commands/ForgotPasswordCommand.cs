using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Interfaces;

namespace ASD.SeedProjectNet8.Application.Identity.Commands;

public record ForgotPasswordCommand(string Email) : IRequest<Result>;

internal sealed class ForgotPasswordCommandHandler(IAuthService authService) : IRequestHandler<ForgotPasswordCommand, Result>
{
    public async Task<Result> Handle(ForgotPasswordCommand request, CancellationToken cancellationToken)
    {
        return await authService.ForgotPasswordAsync(request.Email);
    }
}
