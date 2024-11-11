using Flipify.DTOs;
using Flipify.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Flipify.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class FlipcardsController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly JwtService _jwtService;
        private readonly TokenValidationService _tokenValidationService;

        public FlipcardsController(AppDbContext context, JwtService jwtService, TokenValidationService tokenValidationService)
        {
            _context = context;
            _jwtService = jwtService;
            _tokenValidationService = tokenValidationService;
        }

        #region Set endpoints

        [HttpPost("add-set")]
        public IActionResult AddFlipcardSet([FromBody] CreateFlipcardSetDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid request data.");

            string? username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            User? user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            FlipcardSet? existingSet = _context.FlipcardSets
                .FirstOrDefault(f => f.UserId == user.Id && f.Name == dto.Name);

            if (existingSet != null)
                return BadRequest("A set with this name already exists for this user.");

            FlipcardSet flipcardSet = new()
            {
                UserId = user.Id,
                BaseLanguage = dto.BaseLanguage,
                ForeignLanguage = dto.ForeignLanguage,
                Name = dto.Name
            };

            _context.FlipcardSets.Add(flipcardSet);
            _context.SaveChanges();

            return Ok(flipcardSet);
        }

        [HttpGet("my-sets")]
        public async Task<IActionResult> GetMyFlipcardSets()
        {
            string? accessToken = Request.Cookies["accessToken"];

            (bool isValid, string? errorMessage, User? foundUser) = await _tokenValidationService.ValidateAccessTokenAsync(accessToken);

            if (!isValid)
                return Unauthorized(new { error = errorMessage });

            var flipcardSets = _context.FlipcardSets
                .Where(fs => fs.UserId == Guid.Parse(foundUser.Id.ToString()))
                .Select(fs => new
                {
                    fs.Id,
                    fs.Name,
                    fs.BaseLanguage,
                    fs.ForeignLanguage,
                    fs.CreatedAt,
                    FlipcardCount = _context.Flipcards.Count(f => f.FlipcardSetId == fs.Id),
                })
                .ToList();

            return Ok(flipcardSets);
        }

        [HttpPost("get-flipcards-from-set")]
        public async Task<IActionResult> GetFlipcardsFromSet([FromBody] GetFlipcardsFromSetDto dto)
        {
            string? accessToken = Request.Cookies["accessToken"];

            (bool isValid, string? errorMessage, User? foundUser) = await _tokenValidationService.ValidateAccessTokenAsync(accessToken);

            if (!isValid)
                return Unauthorized(new { error = errorMessage });

            FlipcardSet? flipcardSet = _context.FlipcardSets
                .FirstOrDefault(fs => fs.Id == dto.setId && fs.UserId == foundUser.Id);

            if (flipcardSet == null)
                return NotFound("Flipcard set not found or it doesn't belong to the user.");

            var flipcardsData = _context.Flipcards.Select(f => new
            {
                f.Id,
                f.NativeWord,
                f.ForeignWord,
                f.NativeWordExample,
                f.ForeignWordExample,
                f.LastReviewDate,
                f.NextReviewDate,
                f.IntervalDays,
                f.Ef,
                f.AttemptCount
            }).ToList();

            return Ok(flipcardsData);
        }

        [HttpDelete("remove-set")]
        public IActionResult RemoveFlipcardSetWithFlipcards([FromBody] RemoveFlipcardSetDto dto)
        {
            string? username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            User? user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            FlipcardSet? flipcardSet = _context.FlipcardSets
                .FirstOrDefault(fs => fs.Id == dto.SetId && fs.UserId == user.Id);

            if (flipcardSet == null)
                return NotFound("Flipcard set not found or it doesn't belong to the user.");

            List<Flipcard> flipcards = _context.Flipcards.Where(f => f.FlipcardSetId == dto.SetId).ToList();

            _context.Flipcards.RemoveRange(flipcards);
            _context.FlipcardSets.Remove(flipcardSet);
            _context.SaveChanges();

            return Ok("Flipcard set and its flipcards removed successfully.");
        }

        #endregion

        #region Flipcard endpoints

        [HttpPost("add-flipcard")]
        public IActionResult AddFlipcard([FromBody] CreateFlipcardDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid request data.");

            string? username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            User? user = _context.Users.SingleOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            FlipcardSet? flipcardSet = _context.FlipcardSets.FirstOrDefault(f => f.Id == dto.FlipcardSetId && f.UserId == user.Id);
            if (flipcardSet == null)
                return NotFound("Flipcard set not found or it doesn't belong to the user.");

            Flipcard flipcard = new()
            {
                FlipcardSetId = flipcardSet.Id,
                NativeWord = dto.NativeWord,
                ForeignWord = dto.ForeignWord,
                NativeWordExample = dto.NativeWordExample,
                ForeignWordExample = dto.ForeignWordExample
            };

            _context.Flipcards.Add(flipcard);
            _context.SaveChanges();

            return Ok(flipcard);
        }

        [HttpDelete("remove-flipcard")]
        public IActionResult RemoveFlipcard([FromBody] RemoveFlipcardDto dto)
        {
            string? username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            User? user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            if (!Guid.TryParse(dto.FlipcardId, out Guid flipcardGuid))
                return BadRequest("Invalid Flipcard ID format.");

            Flipcard? flipcard = _context.Flipcards.FirstOrDefault(f => f.Id == flipcardGuid && f.FlipcardSet.UserId == user.Id);
            if (flipcard == null)
                return NotFound("Flipcard not found or it doesn't belong to the user.");

            _context.Flipcards.Remove(flipcard);
            _context.SaveChanges();

            return Ok("Flipcard removed successfully.");
        }

        [HttpPut("edit-flipcard")]
        public IActionResult EditFlipcard([FromBody] UpdateFlipcardDto dto)
        {
            string? username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            User? user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            Flipcard? flipcard = _context.Flipcards.FirstOrDefault(f => f.Id == dto.FlipcardId && f.FlipcardSet.UserId == user.Id);
            if (flipcard == null)
                return NotFound("Flipcard not found or it doesn't belong to the user.");

            if (flipcard.AttemptCount == 0)
            {
                flipcard.NextReviewDate = DateTime.UtcNow.AddDays(1);
                flipcard.IntervalDays = 1;
            }
            else
            {
                switch (dto.Score)
                {
                    case 0:
                    case 1:
                    case 2:
                        flipcard.NextReviewDate = DateTime.UtcNow.AddDays(1);
                        flipcard.IntervalDays = 1;
                        break;

                    case 3:
                        flipcard.NextReviewDate = DateTime.UtcNow.AddDays(2);
                        flipcard.IntervalDays = 2;
                        break;

                    case 4:
                    case 5:
                        decimal newEf = flipcard.Ef + (0.1m - (5 - dto.Score) * (0.08m + (5 - dto.Score) * 0.02m));
                        flipcard.Ef = newEf < 1.3m ? 1.3m : newEf;
                        flipcard.IntervalDays = (int)(flipcard.IntervalDays * flipcard.Ef);

                        if (flipcard.IntervalDays > 30)
                        {
                            flipcard.IntervalDays = 30;
                        }

                        flipcard.NextReviewDate = DateTime.UtcNow.AddDays(flipcard.IntervalDays);
                        break;
                }
            }

            flipcard.LastReviewDate = DateTime.UtcNow;
            flipcard.AttemptCount++;

            _context.SaveChanges();

            return Ok(flipcard);
        }

        #endregion
    }
}
