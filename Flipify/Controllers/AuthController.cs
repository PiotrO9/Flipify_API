﻿using Flipify.DTOs;
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
            return BadRequest("Invalid token.");

        var user = _context.Users.SingleOrDefault(u => u.Email == emailClaim.Value);
        if (user == null)
            return BadRequest("User not found.");

        user.IsVerified = true;
        _context.SaveChanges();

        return Ok("Email verified successfully!");
    }

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        if (_context.Users.Any(u => u.Username == dto.Username))
            return BadRequest("User already exists");

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

        return Ok("User created successfully. Please verify your email.");
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = _context.Users.SingleOrDefault(u => u.Username == dto.Username);
        if (user == null || !VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            return Unauthorized("Invalid credentials");

        if (!user.IsVerified)
            return Unauthorized("Please verify your email before logging in.");

        user.LastLoggedInDate = DateTime.UtcNow;
        _context.SaveChanges();

        var token = _jwtService.GenerateToken(user);

        return Ok(new { token });
    }


    [HttpDelete("delete")]
    [Authorize]
    public IActionResult DeleteUser([FromBody] DeleteUserDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = _context.Users.SingleOrDefault(u => u.Username == dto.Username && u.Email == dto.Email);

        if (user == null)
            return BadRequest("User not found");

        if (!VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            return Unauthorized("Invalid credentials");

        _context.Users.Remove(user);
        _context.SaveChanges();

        return Ok("User deleted successfully");
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