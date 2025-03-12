using ASD.SeedProjectNet8.Application.Identity.Interfaces;
using ASD.SeedProjectNet8.Application.Identity.Models;

namespace ASD.SeedProjectNet8.Application.Identity.Commands;

public record LoginRequestCommand(
    string Username,
    string Password,
    bool RememberMe = false) : IRequest<AuthenticatedResponse>;

internal sealed class LoginRequestCommandHandler(IAuthService authService)
    : IRequestHandler<LoginRequestCommand, AuthenticatedResponse>
{
    public async Task<AuthenticatedResponse> Handle(LoginRequestCommand request, CancellationToken cancellationToken)
    {
        return await authService.LoginAsync(request.Username, request.Password, request.RememberMe);
    }
}
