namespace ASD.SeedProjectNet8.Application.Identity.Exceptions;

public class AuthenticationException : Exception
{
    public AuthenticationException() : base("Authentication failed")
    {
    }

    public AuthenticationException(string message) : base(message)
    {
    }

    public AuthenticationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
