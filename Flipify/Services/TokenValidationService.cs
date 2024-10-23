using Microsoft.EntityFrameworkCore;

public class TokenValidationService
{
    private readonly JwtService _jwtService;
    private readonly AppDbContext _context;

    public TokenValidationService(JwtService jwtService, AppDbContext context)
    {
        _jwtService = jwtService;
        _context = context;
    }

    public async Task<(bool IsValid, string? ErrorMessage, User? User)> ValidateAccessTokenAsync(string? accessToken)
    {
        if (string.IsNullOrEmpty(accessToken))
            return (false, "No access token provided.", null);

        var claimsPrincipal = _jwtService.ValidateToken(accessToken);
        if (claimsPrincipal == null)
            return (false, "Invalid access token.", null);

        var userName = _jwtService.GetUserIdFromToken(accessToken);
        if (userName == null)
            return (false, "Invalid access token.", null);

        User? foundUser = await _context.Users.Where(u => u.Username == userName).FirstOrDefaultAsync();
        if (foundUser == null)
            return (false, "No user found.", null);

        return (true, null, foundUser);
    }
}
