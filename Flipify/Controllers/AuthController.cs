using Flipify.DTOs;
using Flipify.Models;
using Flipify.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Data.Entity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly JwtService _jwtService;
    private readonly EmailService _emailService;
    private readonly TokenValidationService _tokenValidationService;
    private readonly IConfiguration _config;

    public AuthController(AppDbContext context, JwtService jwtService, EmailService emailService, TokenValidationService tokenValidationService, IConfiguration config)
    {
        _context = context;
        _jwtService = jwtService;
        _emailService = emailService;
        _tokenValidationService = tokenValidationService;
        _config = config;
    }

    [HttpGet("verify-email")]
    public async Task<ActionResult<string>> VerifyEmail(string token)
    {
        JwtSecurityTokenHandler tokenHandler = new();
        byte[]? key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]);

        try
        {
            ClaimsPrincipal? principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            Claim? emailClaim = principal.Claims.FirstOrDefault(c => c.Type == "Email");
            if (emailClaim == null)
                return BadRequest(new { error = "Invalid token." });

            User? user = await _context.Users.SingleOrDefaultAsync(u => u.Email == emailClaim.Value);
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

        PasswordHashSalt? passwordHashSalt = HashPassword(dto.Password);

        User user = new()
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

        string? verificationToken = _jwtService.GenerateVerificationToken(user);
        _emailService.SendVerificationEmail(user, verificationToken);

        return Ok("User created successfully. Please verify your email.");
    }

    [HttpPost("login")]
    public async Task<ActionResult> Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        User? user = _context.Users.Where(u => u.Username == dto.Username).FirstOrDefault();
        if (user == null || !VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            return Unauthorized(new { error = "Invalid credentials." });

        if (!user.IsVerified)
            return Unauthorized(new { error = "Please verify your email before logging in." });

        user.LastLoggedInDate = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        string? accessToken = _jwtService.GenerateToken(user);
        string? refreshToken = _jwtService.GenerateRefreshToken();

        SaveRefreshTokenToDatabase(user.Id, refreshToken);

        CookieOptions accessCookieOptions = new()
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
        string? accessToken = Request.Cookies["accessToken"];

        (bool isValid, string? errorMessage, User? foundUser) = await _tokenValidationService.ValidateAccessTokenAsync(accessToken);

        if (!isValid)
            return Unauthorized(new { error = errorMessage });

        RefreshToken? storedRefreshToken = _context.RefreshTokens
            .Where(rt => rt.UserId == Guid.Parse(foundUser.Id.ToString()) && !rt.IsRevoked && rt.ExpiresAt > DateTime.UtcNow)
            .FirstOrDefault();

        if (storedRefreshToken != null)
        {
            storedRefreshToken.IsRevoked = true;
            await _context.SaveChangesAsync();
        }

        CookieOptions cookieOptions = new()
        {
            Expires = DateTime.UtcNow.AddDays(-1),
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict
        };
        Response.Cookies.Delete("accessToken", cookieOptions);

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
        string? accessToken = Request.Cookies["accessToken"];

        if (string.IsNullOrEmpty(accessToken))
            return Unauthorized(new { error = "No access token provided." });

        ClaimsPrincipal? claimsPrincipal = _jwtService.ValidateToken(accessToken);
        if (claimsPrincipal == null)
            return Unauthorized(new { error = "Invalid or expired access token." });

        string? userId = _jwtService.GetUserIdFromToken(accessToken);

        return Ok(new { message = "Token is valid" });
    }

    private void SaveRefreshTokenToDatabase(Guid userId, string refreshToken)
    {
        DateTime expiryDate = DateTime.UtcNow.AddDays(30);
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
        using (HMACSHA512 hmac = new())
        {
            byte[]? salt = hmac.Key;
            byte[]? hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

            return new PasswordHashSalt
            {
                Hash = Convert.ToBase64String(hash),
                Salt = Convert.ToBase64String(salt)
            };
        }
    }

    private bool VerifyPassword(string password, string storedHash, string storedSalt)
    {
        using (HMACSHA512 hmac = new(Convert.FromBase64String(storedSalt)))
        {
            byte[]? computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(computedHash) == storedHash;
        }
    }
}

public class PasswordHashSalt
{
    public string Hash { get; set; }
    public string Salt { get; set; }
}
