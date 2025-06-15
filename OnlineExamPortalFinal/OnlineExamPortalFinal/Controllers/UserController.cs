using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OnlineExamPortalFinal.Data;
using OnlineExamPortalFinal.DTOs;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace OnlineExamPortal.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _env;

        public UserController(ApplicationDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }
        private string HashPassword (string password)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytes);
        }

        [HttpGet("profile")]
        public IActionResult GetProfile()
        {
            int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));

            var user = _context.Users.FirstOrDefault(u => u.UserId == userId);

            if (user == null)
                return NotFound("User not found.");

            // Return the image URL as well!
            var result = new
            {
                Name = user.Name,
                Email = user.Email,
                Role = user.Role,
                ProfileImageUrl = user.ProfileImageUrl // <-- this line added!
            };

            return Ok(result);
        }

        [HttpPut("profile")]
        public IActionResult UpdateProfile(UpdateProfileDto dto)
        {
            int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

            var user = _context.Users.FirstOrDefault(u => u.UserId == userId);
            if (user == null)
                return NotFound("User not found.");

            user.Name = dto.Name;
            user.Email = dto.Email;

            _context.SaveChanges();

            return Ok("Profile updated.");
        }

        [Authorize(Roles = "Student")]
        [HttpPost("upload-photo")]
        public async Task<IActionResult> UploadPhoto(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest("No file uploaded.");

            var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
            var user = await _context.Users.FindAsync(userId);

            if (user == null)
                return NotFound("User not found.");

            var uploadsDir = Path.Combine(_env.WebRootPath ?? "wwwroot", "uploads");
            if (!Directory.Exists(uploadsDir))
                Directory.CreateDirectory(uploadsDir);

            var fileName = $"{Guid.NewGuid()}{Path.GetExtension(file.FileName)}";
            var filePath = Path.Combine(uploadsDir, fileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            user.ProfileImageUrl = $"/uploads/{fileName}";
            await _context.SaveChangesAsync();

            return Ok(new { message = "Photo uploaded successfully", url = user.ProfileImageUrl });
        }

        public class ChangePasswordDto
        {
            public string CurrentPassword { get; set; }
            public string NewPassword { get; set; }
        }

        [Authorize(Roles = "Student")]
        [HttpPost("change-password")]
        public IActionResult ChangePassword([FromBody] ChangePasswordDto dto)
        {
            var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
            var user = _context.Users.FirstOrDefault(u => u.UserId == userId);

            if (user == null)
                return NotFound("User not found.");

            // Use BCrypt to verify current password
            if (!BCrypt.Net.BCrypt.Verify(dto.CurrentPassword, user.PasswordHash))
                return BadRequest("Current password is incorrect.");

            // Hash the new password with BCrypt
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);
            _context.SaveChanges();

            return Ok("Password changed successfully.");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("all-users")]
        public IActionResult GetAllUsers()
        {
            var users = _context.Users.Select(u => new
            {
                u.UserId,
                u.Name,
                u.Email,
                u.Role,
                u.ProfileImageUrl
            }).ToList();

            return Ok(users);
        }

        [HttpGet("dashboard-metrics")]
        public async Task<IActionResult> GetDashboardMetrics()
        {
            var userIdString = User.Claims.FirstOrDefault(c => c.Type == "sub" || c.Type.Contains("nameidentifier"))?.Value;
            if (string.IsNullOrEmpty(userIdString) || !int.TryParse(userIdString, out int userId))
                return Unauthorized();

            // All exams (active)
            var allExams = await _context.Exams.Where(e => e.IsActive).ToListAsync();

            // All user attempts (Responses)
            var attempts = await _context.Responses
                .Include(r => r.Exam)
                .Where(a => a.UserId == userId)
                .ToListAsync();

            // Build AllExams list
            var allExamsList = allExams.Select(e => new AllExamDto
            {
                ExamId = e.ExamId,
                ExamName = e.Title,
                TotalMarks = e.TotalMarks,
                Duration = e.Duration + " min"
            }).ToList();

            // Build Attempts list
            var attemptsList = attempts.Select(a => new UserExamAttemptDto
            {
                ExamId = a.ExamId,
                ExamName = a.Exam.Title,
                Score = a.MarksObtained,
                Passed = a.IsPassed,
                AttemptDate = a.Timestamp
            }).ToList();

            // Calculate unique attempted exams
            var uniqueAttemptedExamIds = attemptsList.Select(a => a.ExamId).Distinct().ToList();

            // Calculate passed exams
            var passedExamIds = attemptsList.Where(a => a.Passed).Select(a => a.ExamId).Distinct().ToHashSet();

            // Calculate failed exams (attempted but never passed)
            var failedExamIds = attemptsList
                .Where(a => !a.Passed && !passedExamIds.Contains(a.ExamId))
                .Select(a => a.ExamId)
                .Distinct();

            // Best Score Exam (sum of marks per exam)
            var bestScoreExam = attempts
                .GroupBy(a => a.ExamId)
                .Select(g => new
                {
                    ExamName = g.First().Exam.Title,
                    Score = g.Sum(x => x.MarksObtained),
                    ExamId = g.Key
                })
                .OrderByDescending(x => x.Score)
                .FirstOrDefault();

            BestScoreExamDto? bestExamDto = null;
            if (bestScoreExam != null)
            {
                bestExamDto = new BestScoreExamDto
                {
                    Name = bestScoreExam.ExamName,
                    Score = bestScoreExam.Score
                };
            }

            // Last Attempt (latest by Timestamp)
            var lastAttempt = attempts
                .OrderByDescending(a => a.Timestamp)
                .FirstOrDefault();

            LastAttemptDto? lastAttemptDto = null;
            if (lastAttempt != null)
            {
                var examName = lastAttempt.Exam.Title;
                var score = attempts
                    .Where(a => a.ExamId == lastAttempt.ExamId && a.Timestamp == lastAttempt.Timestamp)
                    .Sum(a => a.MarksObtained);

                lastAttemptDto = new LastAttemptDto
                {
                    Name = examName,
                    Date = lastAttempt.Timestamp,
                    Score = score,
                    Result = lastAttempt.IsPassed ? "Passed" : "Failed"
                };
            }

            // Exam-wise Rankings
            var examRankings = new List<ExamRankingDto>();
            foreach (var examId in uniqueAttemptedExamIds)
            {
                var allResponses = await _context.Responses
                    .Where(r => r.ExamId == examId)
                    .ToListAsync();

                var userScore = allResponses.Where(r => r.UserId == userId).Sum(r => r.MarksObtained);

                var userScores = allResponses
                    .GroupBy(r => r.UserId)
                    .Select(g => new { UserId = g.Key, Score = g.Sum(x => x.MarksObtained) })
                    .OrderByDescending(x => x.Score)
                    .ToList();

                var rank = userScores.FindIndex(x => x.UserId == userId) + 1;
                var topperScore = userScores.FirstOrDefault()?.Score ?? 0;
                var examName = _context.Exams.FirstOrDefault(e => e.ExamId == examId)?.Title ?? "Unknown Exam";

                examRankings.Add(new ExamRankingDto
                {
                    ExamId = examId,
                    ExamName = examName,
                    Rank = rank,
                    TotalParticipants = userScores.Count,
                    Score = userScore,
                    TopperScore = topperScore
                });
            }

            // Available Exams (not attempted)
            var attemptedExamIdSet = new HashSet<int>(uniqueAttemptedExamIds);
            var availableExams = await _context.Exams
                .Where(e => e.IsActive && !attemptedExamIdSet.Contains(e.ExamId))
                .ToListAsync();

            var availableExamDtos = availableExams.Select(e => new AvailableExamDto
            {
                ExamId = e.ExamId,
                ExamName = e.Title,
                TotalMarks = e.TotalMarks,
                Duration = e.Duration + " min"
            }).ToList();

            var metrics = new DashboardMetricsDto
            {
                TotalExams = allExamsList.Count,
                Attempted = uniqueAttemptedExamIds.Count,
                Passed = passedExamIds.Count,
                Failed = failedExamIds.Count(),
                BestScoreExam = bestExamDto,
                LastAttempt = lastAttemptDto,
                Rankings = examRankings,
                AvailableExams = availableExamDtos,
                AllExams = allExamsList,
                Attempts = attemptsList
            };

            return Ok(metrics);
        }
    }
}
