namespace ASD.SeedProjectNet8.Application.Identity.Exceptions;

public class EmailConfirmationException : AuthenticationException
{
    public EmailConfirmationException() : base("Email not confirmed")
    {
    }
}
