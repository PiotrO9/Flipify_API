using Flipify.Models;

public class User
{
    public Guid Id { get; set; }

    public string Username { get; set; }

    public string PasswordHash { get; set; }

    public string PasswordSalt { get; set; }

    public string Email { get; set; }

    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;

    public DateTime? LastLoggedInDate { get; set; }

    public bool IsVerified { get; set; } = false;
    public List<RefreshToken>? RefreshTokens { get; set; }
}
