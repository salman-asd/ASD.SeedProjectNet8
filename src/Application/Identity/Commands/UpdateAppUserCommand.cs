using ASD.SeedProjectNet8.Application.Common.Interfaces;
using ASD.SeedProjectNet8.Application.Common.Models;

namespace ASD.SeedProjectNet8.Application.Identity.Commands;

public record UpdateAppUserCommand(
     string Id,
     string Username,
     string Email,
     string FirstName,
     string LastName,
     string PhoneNumber,
     bool IsActive,
     List<string>? Roles
    ) : IRequest<Result>;

internal sealed class UpdateAppUserCommandHandler(IIdentityService identityService)
    : IRequestHandler<UpdateAppUserCommand, Result>
{
    public async Task<Result> Handle(UpdateAppUserCommand request, CancellationToken cancellationToken)
    {
        return await identityService.UpdateUserAsync(request, cancellationToken);
    }
}
