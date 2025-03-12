namespace ASD.SeedProjectNet8.Infrastructure.Identity;

public class RefreshToken
{
    public int Id { get; set; }
    public string Token { get; set; } = string.Empty;
    public DateTimeOffset Expires { get; set; }
    public DateTimeOffset Created { get; set; }
    public DateTimeOffset? Revoked { get; set; }
    public string UserId { get; set; }

    public bool IsExpired => DateTimeOffset.UtcNow >= Expires;
    public bool IsRevoked => Revoked != null;
    public bool IsActive => !IsRevoked && !IsExpired;

    public ApplicationUser ApplicationUser { get; set; } = default!;
}

