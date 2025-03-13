namespace ASD.SeedProjectNet8.Application.Identity.Exceptions;

public class RefreshTokenException : AuthenticationException
{
    public RefreshTokenException() : base("Invalid or expired refresh token")
    {
    }
}
