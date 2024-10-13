using Flipify.DTOs;
using Flipify.Models;
using Flipify.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
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
    public async Task<ActionResult<object>> Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == dto.Username);
        if (user == null || !VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            return Unauthorized(new { error = "Invalid credentials." });

        if (!user.IsVerified)
            return Unauthorized(new { error = "Please verify your email before logging in." });

        user.LastLoggedInDate = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        // Generate JWT token
        var accessToken = _jwtService.GenerateToken(user);
        var refreshToken = _jwtService.GenerateRefreshToken();

        // Save the refresh token to the database
        SaveRefreshTokenToDatabase(user.Id, refreshToken);

        // Set the access token in an HTTP-only cookie
        var accessCookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,  // Set to true in production
            Expires = DateTime.Now.AddMinutes(15), // Set access token expiration
            SameSite = SameSiteMode.Lax
        };
        Response.Cookies.Append("accessToken", accessToken, accessCookieOptions);

        // Set the refresh token in an HTTP-only cookie
        var refreshCookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,  // Set to true in production
            Expires = DateTime.Now.AddDays(30),
            SameSite = SameSiteMode.Lax
        };
        Response.Cookies.Append("refreshToken", refreshToken, refreshCookieOptions);

        return Ok(new { accessToken });
    }


    [HttpPost("refresh")]
    public async Task<ActionResult<object>> Refresh()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(refreshToken))
        {
            return Unauthorized("No refresh token provided.");
        }

        var storedToken = await _context.RefreshTokens
            .SingleOrDefaultAsync(t => t.Token == refreshToken && !t.IsRevoked);

        if (storedToken == null || storedToken.ExpiresAt < DateTime.UtcNow)
        {
            return Unauthorized("Invalid or expired refresh token.");
        }

        var user = await _context.Users.FindAsync(storedToken.UserId);
        var accessToken = _jwtService.GenerateToken(user);

        return Ok(new { accessToken });
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (!string.IsNullOrEmpty(refreshToken))
        {
            var storedToken = await _context.RefreshTokens.SingleOrDefaultAsync(t => t.Token == refreshToken);
            if (storedToken != null)
            {
                storedToken.IsRevoked = true;
                await _context.SaveChangesAsync();
            }

            Response.Cookies.Delete("refreshToken");
        }

        return Ok();
    }

    [HttpGet("validate-token")]
    [Authorize]
    public async Task<IActionResult> ValidateToken()
    {
        // Retrieve the access token from the HTTP-only cookie
        var accessToken = Request.Cookies["accessToken"];
        if (string.IsNullOrEmpty(accessToken))
        {
            return Unauthorized(new { error = "No access token provided." });
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]);

        try
        {
            // Validate the access token
            var principal = tokenHandler.ValidateToken(accessToken, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true, // Ensures the token has not expired
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            // If access token is valid, return 200 OK
            return Ok(new { message = "Access token is valid." });
        }
        catch (SecurityTokenExpiredException)
        {
            // If access token is expired, attempt to refresh it using the refresh token

            // Retrieve the refresh token from the HTTP-only cookie
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                return Unauthorized(new { error = "Refresh token not provided or expired." });
            }

            // Validate the refresh token
            var storedRefreshToken = await _context.RefreshTokens
                .SingleOrDefaultAsync(t => t.Token == refreshToken && !t.IsRevoked);

            if (storedRefreshToken == null || storedRefreshToken.ExpiresAt < DateTime.UtcNow)
            {
                return Unauthorized(new { error = "Invalid or expired refresh token." });
            }

            // If refresh token is valid, generate a new access token
            var user = await _context.Users.FindAsync(storedRefreshToken.UserId);
            var newAccessToken = _jwtService.GenerateToken(user);

            // Optionally: set the new access token in the cookie (you can also return it in the response body)
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Set to true in production
                Expires = DateTime.Now.AddMinutes(30) // Set access token expiration
            };
            Response.Cookies.Append("accessToken", newAccessToken, cookieOptions);

            // Return a new access token to the client
            return Ok(new { accessToken = newAccessToken });
        }
        catch (SecurityTokenException)
        {
            return Unauthorized(new { error = "Invalid access token." });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = $"Internal server error: {ex.Message}" });
        }
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
