namespace ASD.SeedProjectNet8.Application.Identity.Exceptions;

public class InvalidTokenException : AuthenticationException
{
    public InvalidTokenException() : base("Invalid or expired token")
    {
    }
}
