using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Interfaces;
using ASD.SeedProjectNet8.Application.Identity.Models;

namespace ASD.SeedProjectNet8.Application.Identity.Commands;
public record RefreshTokenRequestCommand(string RefreshToken, string AccessToken)
    : IRequest<AuthenticatedResponse>;


internal sealed class RefreshTokenCommandHandler(IAuthService authService)
    : IRequestHandler<RefreshTokenRequestCommand, AuthenticatedResponse>
{
    public async Task<AuthenticatedResponse> Handle(RefreshTokenRequestCommand request, CancellationToken cancellationToken)
    {
        return await authService
            .RefreshTokenAsync(request.RefreshToken, request.AccessToken, cancellationToken);
    }
}
