namespace ASD.SeedProjectNet8.Application.Identity.Exceptions;


public class InvalidCredentialsException : AuthenticationException
{
    public InvalidCredentialsException() : base("Invalid username or password")
    {
    }
}
