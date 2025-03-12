namespace ASD.SeedProjectNet8.Application.Identity.Interfaces;

public interface ICustomAuthorizationService
{
    //Task<bool> AuthorizeAsync(string userId, string policyName, CancellationToken cancellation = default);
    //Task<bool> IsInRoleAsync(string userId, string role, CancellationToken cancellation = default);

    Task<bool> IsInRoleAsync(string userId, string role);

    Task<bool> AuthorizeAsync(string userId, string policyName);


}
