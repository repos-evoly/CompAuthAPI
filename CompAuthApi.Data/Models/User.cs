// CompAuthApi.Data.Models/User.cs
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models
{
    [Table("Users")]
    [Index(nameof(Email), IsUnique = true, Name = "Unique_Email")]
    [Index(nameof(Username), IsUnique = true, Name = "Unique_Username")]
    public class User : Auditable
    {
        [Key]
        public int Id { get; set; }

        [Required, MaxLength(150)]
        public string Username { get; set; } = string.Empty;

        [Required, MaxLength(150)]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Password { get; set; } = string.Empty;

        public string? PasswordToken { get; set; }

        [DefaultValue(true)]
        public bool Active { get; set; }

        [MaxLength(10)]
        public string? BranchId { get; set; }

        [DefaultValue(1)]
        public int RoleId { get; set; }
        public Role? Role { get; set; }

        public required UserSecurity UserSecurity { get; set; }
    }
}
