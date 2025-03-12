using Microsoft.AspNetCore.Identity;

namespace ASD.SeedProjectNet8.Infrastructure.Identity;

public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public bool IsActive { get; set; }
}
