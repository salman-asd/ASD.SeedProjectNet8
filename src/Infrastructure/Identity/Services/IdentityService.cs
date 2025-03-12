using System.Transactions;
using ASD.SeedProjectNet8.Application.Common.Interfaces;
using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Commands;
using ASD.SeedProjectNet8.Infrastructure.Identity.Entities;
using ASD.SeedProjectNet8.Infrastructure.Identity.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace ASD.SeedProjectNet8.Infrastructure.Identity.Services;

public class IdentityService(
    UserManager<ApplicationUser> userManager,
    IUserClaimsPrincipalFactory<ApplicationUser> userClaimsPrincipalFactory,
    IAuthorizationService authorizationService,
    IdentityDbContext identityContext) : IIdentityService
{
    public async Task<string?> GetUserNameAsync(string userId)
    {
        var user = await userManager.FindByIdAsync(userId);

        return user?.UserName;
    }

    //public async Task<(Result Result, string UserId)> CreateUserAsync(string userName, string password, )
    //{
    //    var user = new ApplicationUser
    //    {
    //        UserName = userName,
    //        Email = userName,
    //    };

    //    var result = await _userManager.CreateAsync(user, password);

    //    return (result.ToApplicationResult(), user.Id);
    //}

    public async Task<Result<string>> CreateUserAsync(
        CreateAppUserCommand command,
        CancellationToken cancellation = default)
    {
        // Use TransactionScope to manage transactions across multiple operations
        using var transaction = new TransactionScope(
            TransactionScopeAsyncFlowOption.Enabled);

        try
        {
            // Create the user using UserManager
            var user = new ApplicationUser
            {
                UserName = command.Username,
                Email = command.Email,
                FirstName = command.FirstName,
                LastName = command.LastName,
                IsActive = command.IsActive,
                PhoneNumber = command.PhoneNumber
            };

            var createUserResult = await userManager.CreateAsync(user, command.Password);
            if (!createUserResult.Succeeded)
            {
                return createUserResult.ToApplicationResult<string>(string.Empty);
            }

            // Add roles if specified
            //if (command.Roles?.Count > 0)
            //{
            //    await _userManager.AddToRolesAsync(user, command.Roles);
            //    await _identityContext.SaveChangesAsync(cancellation);
            //}

            // Mark transaction as complete
            transaction.Complete();

            return Result<string>.Success(user.Id);
        }
        catch (Exception ex)
        {
            // TransactionScope will automatically roll back if `Complete` is not called
            throw new Exception("An error occured while creating the user", ex);
            //return Result.Failure<string>(
            //    Error.Failure(ErrorMessages.UNABLE_CREATE_USER, $"An error occurred: {ex.Message}")
            //);
        }
    }

    public async Task<Result> UpdateUserAsync(
        UpdateAppUserCommand command,
        CancellationToken cancellation = default)
    {
        // Begin a transaction to ensure atomicity
        await using var transaction = await identityContext.Database.BeginTransactionAsync(cancellation);

        try
        {
            // Find the user using UserManager
            var user = await userManager.FindByIdAsync(command.Id);
            if (user == null)
                throw new NotFoundException(nameof(ApplicationUser), command.Id);

            // Update user properties
            user.UserName = command.Username;
            user.Email = command.Email;
            user.FirstName = command.FirstName;
            user.LastName = command.LastName;
            user.IsActive = command.IsActive;
            user.PhoneNumber = command.PhoneNumber;

            // Update the user
            var updateResult = await userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
                throw new Exception(string.Join(", ", updateResult.Errors.Select(e => e.Description)));

            // Update roles (if specified)
            //if (command.Roles?.Count > 0)
            //{
            //    var roleUpdateResult = await UpdateUserRolesAsync(command.Roles, user, cancellation);
            //    if (!roleUpdateResult.IsSuccess)
            //        return roleUpdateResult; // Rollback transaction if role update fails
            //}

            // Commit the transaction
            await transaction.CommitAsync(cancellation);
            return Result.Success();
        }
        catch (Exception ex)
        {
            // Rollback the transaction in case of errors
            await transaction.RollbackAsync(cancellation);
            throw new Exception("An error occured while updating the user", ex);
            //return Result.Failure(Error.Failure("User.Update", $"An error occurred: {ex.Message}"));
        }
    }


    public async Task<Result> DeleteUserAsync(string userId)
    {
        var user = await userManager.FindByIdAsync(userId);

        return user != null ? await DeleteUserAsync(user) : Result.Success();
    }

    public async Task<Result> DeleteUserAsync(ApplicationUser user)
    {
        var result = await userManager.DeleteAsync(user);

        return result.ToApplicationResult();
    }
}
