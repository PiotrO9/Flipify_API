using Flipify.DTOs;
using Flipify.Helpers;
using Flipify.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;

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
    public IActionResult VerifyEmail(string token)
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
                return BadRequest(ApiResponseHelper.CreateErrorResponse<string>("Invalid token.", 400));

            var user = _context.Users.SingleOrDefault(u => u.Email == emailClaim.Value);
            if (user == null)
                return BadRequest(ApiResponseHelper.CreateErrorResponse<string>("User not found.", 400));

            user.IsVerified = true;
            _context.SaveChanges();

            return Ok(ApiResponseHelper.CreateSuccessResponse<string>("Email verified successfully."));
        }
        catch (SecurityTokenException)
        {
            return BadRequest(ApiResponseHelper.CreateErrorResponse<string>("Invalid token format.", 400));
        }
        catch (Exception ex)
        {
            return StatusCode(500, ApiResponseHelper.CreateErrorResponse<string>($"Internal server error: {ex.Message}", 500));
        }
    }

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponseHelper.CreateErrorResponse<string>("Invalid request data.", 400));

        if (_context.Users.Any(u => u.Username == dto.Username))
            return BadRequest(ApiResponseHelper.CreateErrorResponse<string>("User already exists.", 400));

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
        _context.SaveChanges();

        var verificationToken = _jwtService.GenerateVerificationToken(user);
        _emailService.SendVerificationEmail(user, verificationToken);

        return Ok(ApiResponseHelper.CreateSuccessResponse<string>("User created successfully. Please verify your email."));
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponseHelper.CreateErrorResponse<string>("Invalid request data.", 400));

        var user = _context.Users.SingleOrDefault(u => u.Username == dto.Username);
        if (user == null || !VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            return Unauthorized(ApiResponseHelper.CreateErrorResponse<string>("Invalid credentials.", 401));

        if (!user.IsVerified)
            return Unauthorized(ApiResponseHelper.CreateErrorResponse<string>("Please verify your email before logging in.", 401));

        user.LastLoggedInDate = DateTime.UtcNow;
        _context.SaveChanges();

        var token = _jwtService.GenerateToken(user);

        return Ok(ApiResponseHelper.CreateSuccessResponse(new { token }, "Login successful."));
    }

    [HttpDelete("delete")]
    [Authorize]
    public IActionResult DeleteUser([FromBody] DeleteUserDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponseHelper.CreateErrorResponse<string>("Invalid request data.", 400));

        var user = _context.Users.SingleOrDefault(u => u.Username == dto.Username && u.Email == dto.Email);
        if (user == null)
            return BadRequest(ApiResponseHelper.CreateErrorResponse<string>("User not found.", 400));

        if (!VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            return Unauthorized(ApiResponseHelper.CreateErrorResponse<string>("Invalid credentials.", 401));

        _context.Users.Remove(user);
        _context.SaveChanges();

        return Ok(ApiResponseHelper.CreateSuccessResponse<string>("User deleted successfully."));
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