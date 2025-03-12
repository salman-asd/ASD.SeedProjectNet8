using ASD.SeedProjectNet8.Application.Common.Interfaces;
using ASD.SeedProjectNet8.Application.Common.Models;

namespace ASD.SeedProjectNet8.Application.Identity.Commands;

public record CreateAppUserCommand(
    string Username,
    string Password,
    string Email,
    string FirstName,
    string LastName,
    string PhoneNumber,
    bool IsActive): IRequest<Result<string>>;

internal sealed class CreateAppUserCommandHandler(IIdentityService identityService) : IRequestHandler<CreateAppUserCommand, Result<string>>
{
    public async Task<Result<string>> Handle(CreateAppUserCommand request, CancellationToken cancellationToken)
    {
        return await identityService.CreateUserAsync(request, cancellationToken);
    }
}
