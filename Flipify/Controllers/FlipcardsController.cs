using Flipify.DTOs;
using Flipify.Models;
using Microsoft.AspNetCore.Authorization;
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

        public FlipcardsController(AppDbContext context)
        {
            _context = context;
        }

        #region Set endpoints

        [HttpPost("add-set")]
        public IActionResult AddFlipcardSet([FromBody] CreateFlipcardSetDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid request data.");

            var username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            var user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            var existingSet = _context.FlipcardSets
                .FirstOrDefault(f => f.UserId == user.Id && f.Name == dto.Name);

            if (existingSet != null)
                return BadRequest("A set with this name already exists for this user.");

            var flipcardSet = new FlipcardSet
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
        public IActionResult GetMyFlipcardSets()
        {
            var username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            var user = _context.Users.SingleOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            var flipcardSets = _context.FlipcardSets
                .Where(fs => fs.UserId == user.Id)
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

        [HttpDelete("remove-set")]
        public IActionResult RemoveFlipcardSetWithFlipcards([FromBody] RemoveFlipcardSetDto dto)
        {
            var username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            var user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            var flipcardSet = _context.FlipcardSets
                .FirstOrDefault(fs => fs.Id == dto.SetId && fs.UserId == user.Id);

            if (flipcardSet == null)
                return NotFound("Flipcard set not found or it doesn't belong to the user.");

            var flipcards = _context.Flipcards.Where(f => f.FlipcardSetId == dto.SetId).ToList();

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

            var username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            var user = _context.Users.SingleOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            var flipcardSet = _context.FlipcardSets.FirstOrDefault(f => f.Id == dto.FlipcardSetId && f.UserId == user.Id);
            if (flipcardSet == null)
                return NotFound("Flipcard set not found or it doesn't belong to the user.");

            var flipcard = new Flipcard
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
            var username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            var user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            if (!Guid.TryParse(dto.FlipcardId, out Guid flipcardGuid))
                return BadRequest("Invalid Flipcard ID format.");

            var flipcard = _context.Flipcards.FirstOrDefault(f => f.Id == flipcardGuid && f.FlipcardSet.UserId == user.Id);
            if (flipcard == null)
                return NotFound("Flipcard not found or it doesn't belong to the user.");

            _context.Flipcards.Remove(flipcard);
            _context.SaveChanges();

            return Ok("Flipcard removed successfully.");
        }

        [HttpPut("edit-flipcard")]
        public IActionResult EditFlipcard([FromBody] UpdateFlipcardDto dto)
        {
            var username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (username == null)
                return Unauthorized("Invalid token: Username not found.");

            var user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
                return Unauthorized("User not found.");

            var flipcard = _context.Flipcards.FirstOrDefault(f => f.Id == dto.FlipcardId && f.FlipcardSet.UserId == user.Id);
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
