using Flipify.DTOs;
using Flipify.Models;
using Flipify.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Data.Entity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly JwtService _jwtService;
    private readonly EmailService _emailService;
    private readonly IConfiguration _config;

    public AuthController(AppDbContext context, JwtService jwtService, EmailService emailService, IConfiguration config)
    {
        _context = context;
        _jwtService = jwtService;
        _emailService = emailService;
        _config = config;
    }

    [HttpGet("verify-email")]
    public async Task<ActionResult<string>> VerifyEmail(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]);

        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var emailClaim = principal.Claims.FirstOrDefault(c => c.Type == "Email");
            if (emailClaim == null)
                return BadRequest(new { error = "Invalid token." });

            var user = await _context.Users.SingleOrDefaultAsync(u => u.Email == emailClaim.Value);
            if (user == null)
                return BadRequest(new { error = "User not found." });

            user.IsVerified = true;
            await _context.SaveChangesAsync();

            return Ok("Email verified successfully.");
        }
        catch (SecurityTokenException)
        {
            return BadRequest(new { error = "Invalid token format." });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = $"Internal server error: {ex.Message}" });
        }
    }

    [HttpPost("register")]
    public async Task<ActionResult<string>> Register([FromBody] RegisterDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        if (await _context.Users.AnyAsync(u => u.Username == dto.Username))
            return BadRequest(new { error = "User already exists." });

        var passwordHashSalt = HashPassword(dto.Password);

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = dto.Username,
            Email = dto.Email,
            PasswordHash = passwordHashSalt.Hash,
            PasswordSalt = passwordHashSalt.Salt,
            CreatedDate = DateTime.UtcNow
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var verificationToken = _jwtService.GenerateVerificationToken(user);
        _emailService.SendVerificationEmail(user, verificationToken);

        return Ok("User created successfully. Please verify your email.");
    }

    [HttpPost("login")]
    public async Task<ActionResult> Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = _context.Users.Where(u => u.Username == dto.Username).FirstOrDefault();
        if (user == null || !VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            return Unauthorized(new { error = "Invalid credentials." });

        if (!user.IsVerified)
            return Unauthorized(new { error = "Please verify your email before logging in." });

        user.LastLoggedInDate = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        var accessToken = _jwtService.GenerateToken(user);
        var refreshToken = _jwtService.GenerateRefreshToken();

        SaveRefreshTokenToDatabase(user.Id, refreshToken);

        var accessCookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = false,
            SameSite = SameSiteMode.None,
            Expires = DateTime.UtcNow.AddMinutes(15),
        };
        Response.Cookies.Append("accessToken", accessToken, accessCookieOptions);

        return Ok(new { message = "Login successful" });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var accessToken = Request.Cookies["accessToken"];

        if (string.IsNullOrEmpty(accessToken))
            return Unauthorized(new { error = "No access token provided." });

        var claimsPrincipal = _jwtService.ValidateToken(accessToken);
        if (claimsPrincipal == null)
            return Unauthorized(new { error = "Invalid access token." });

        var userName = _jwtService.GetUserIdFromToken(accessToken);
        if (userName == null)
            return Unauthorized(new { error = "Invalid access token." });

        User? foundUser = _context.Users.Where(u => u.Username == userName).FirstOrDefault();
        if (foundUser == null)
            return Unauthorized(new { error = "Invalid access token." });

        var storedRefreshToken = _context.RefreshTokens
            .Where(rt => rt.UserId == Guid.Parse(foundUser.Id.ToString()) && !rt.IsRevoked && rt.ExpiresAt > DateTime.UtcNow)
            .FirstOrDefault();

        if (storedRefreshToken != null)
        {
            storedRefreshToken.IsRevoked = true;
            await _context.SaveChangesAsync();
        }

        var cookieOptions = new CookieOptions
        {
            Expires = DateTime.UtcNow.AddDays(-1),
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict
        };
        Response.Cookies.Delete("accessToken");

        return Ok(new { message = "Logged out successfully" });
    }


    [HttpPost("refresh")]
    public async Task<ActionResult<object>> Refresh()
    {
        return Ok();
    }

    [HttpGet("validate-token")]
    public IActionResult ValidateToken()
    {
        var accessToken = Request.Cookies["accessToken"];

        if (string.IsNullOrEmpty(accessToken))
            return Unauthorized(new { error = "No access token provided." });

        var claimsPrincipal = _jwtService.ValidateToken(accessToken);
        if (claimsPrincipal == null)
            return Unauthorized(new { error = "Invalid or expired access token." });

        var userId = _jwtService.GetUserIdFromToken(accessToken);

        return Ok(new { message = "Token is valid" });
    }

    private void SaveRefreshTokenToDatabase(Guid userId, string refreshToken)
    {
        var expiryDate = DateTime.UtcNow.AddDays(30);
        var userToken = new RefreshToken
        {
            UserId = userId,
            Token = refreshToken,
            ExpiresAt = expiryDate,
            CreatedAt = DateTime.UtcNow
        };
        _context.RefreshTokens.Add(userToken);
        _context.SaveChanges();
    }

    [HttpDelete("delete")]
    [Authorize]
    public async Task<ActionResult<string>> DeleteUser([FromBody] DeleteUserDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == dto.Username && u.Email == dto.Email);
        if (user == null)
            return BadRequest(new { error = "User not found." });

        if (!VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            return Unauthorized(new { error = "Invalid credentials." });

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();

        return Ok("User deleted successfully.");
    }

    private PasswordHashSalt HashPassword(string password)
    {
        using (var hmac = new HMACSHA512())
        {
            var salt = hmac.Key;
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

            return new PasswordHashSalt
            {
                Hash = Convert.ToBase64String(hash),
                Salt = Convert.ToBase64String(salt)
            };
        }
    }

    private bool VerifyPassword(string password, string storedHash, string storedSalt)
    {
        using (var hmac = new HMACSHA512(Convert.FromBase64String(storedSalt)))
        {
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(computedHash) == storedHash;
        }
    }
}

public class PasswordHashSalt
{
    public string Hash { get; set; }
    public string Salt { get; set; }
}
