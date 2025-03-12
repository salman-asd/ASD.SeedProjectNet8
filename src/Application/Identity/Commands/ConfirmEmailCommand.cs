using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Interfaces;

namespace ASD.SeedProjectNet8.Application.Identity.Commands;

public record ConfirmEmailCommand(
    string Email,
    string Token) : IRequest<Result>;

internal sealed class ConfirmEmailCommandHandler(
    IAuthService authService) : IRequestHandler<ConfirmEmailCommand, Result>
{
    public async Task<Result> Handle(ConfirmEmailCommand request, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(request.Token, out var tokenId))
        {
            return Result.Failure(["Invalid token format."]);
        }
        return await authService.ConfirmEmailAsync(request.Email, tokenId, cancellationToken);
    }
}
