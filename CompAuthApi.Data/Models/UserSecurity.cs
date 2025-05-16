using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CompAuthApi.Data.Models
{
    [Table("UserSecurity")]
    public class UserSecurity
    {
        [Key]
        public int Id { get; set; }

        [ForeignKey(nameof(User))]
        public int UserId { get; set; }

        public User? User { get; set; } // Nullable

        public string? TwoFactorSecretKey { get; set; } // Nullable
        public bool IsTwoFactorEnabled { get; set; }
        public string? PasswordResetToken { get; set; } // Nullable
        public DateTimeOffset? PasswordResetTokenExpiry { get; set; }
        public string? QrCodePath { get; set; } // Nullable
        public string? RefreshToken { get; set; } // Nullable
        public DateTimeOffset? RefreshTokenExpiry { get; set; }
        public DateTimeOffset? LastLogin { get; set; }
        public DateTimeOffset? LastLogout { get; set; }
    }
}
