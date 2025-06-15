﻿namespace OnlineExamPortalFinal.Models
{
    public class User
    {
        public int UserId { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;

    // Role can be: "Admin", "Student", "Teacher"
         public string Role { get; set; } = "Student";

    // Navigation Properties
        public ICollection<Response>? Responses { get; set; }

    // Profile Image
        public string? ProfileImageUrl { get; set; }
    }
}
