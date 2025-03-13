namespace ASD.SeedProjectNet8.Application.Identity.Exceptions;

public class UserLockedOutException : AuthenticationException
{
    public UserLockedOutException() : base("User account is locked out")
    {
    }
}
