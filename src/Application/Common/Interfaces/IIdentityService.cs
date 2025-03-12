using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Commands;

namespace ASD.SeedProjectNet8.Application.Common.Interfaces;

public interface IIdentityService
{
    Task<string?> GetUserNameAsync(string userId);

    //Task<bool> IsInRoleAsync(string userId, string role);

    //Task<bool> AuthorizeAsync(string userId, string policyName);

    //Task<(Result Result, string UserId)> CreateUserAsync(string userName, string password);
    Task<Result<string>> CreateUserAsync(CreateAppUserCommand command, CancellationToken cancellation = default);
    Task<Result> UpdateUserAsync(UpdateAppUserCommand command, CancellationToken cancellation = default);


    Task<Result> DeleteUserAsync(string userId);
}
