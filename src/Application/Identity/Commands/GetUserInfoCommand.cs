namespace ASD.SeedProjectNet8.Application.Identity.Commands;

//[Authorize]
//public record GetUserInfoCommand : IRequest<AppUserModel>;

//internal sealed class GetUserInfoCommandHandler(
//    IIdentityService identityService,
//    IUser user) : IRequestHandler<GetUserInfoCommand, AppUserModel>
//{
//    public async Task<AppUserModel> Handle(GetUserInfoCommand request, CancellationToken cancellationToken)
//    {
//        return await identityService.GetUserInfoAsync(user.Id, cancellationToken);
//    }
//}
