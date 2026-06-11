using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models
{
    [Table("UserSessions")]
    [Index(nameof(SessionId), IsUnique = true, Name = "Unique_UserSession_SessionId")]
    [Index(nameof(DeviceId), Name = "IX_UserSessions_DeviceId")]
    [Index(nameof(UserId), nameof(IsActive), Name = "IX_UserSessions_UserId_IsActive")]
    public class UserSession : Auditable
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public int UserId { get; set; }

        public User? User { get; set; }

        [Required, MaxLength(64)]
        public string SessionId { get; set; } = string.Empty;

        [Required, MaxLength(64)]
        public string DeviceId { get; set; } = string.Empty;

        public string? RefreshToken { get; set; }

        [MaxLength(64)]
        public string? IpAddress { get; set; }

        [MaxLength(512)]
        public string? UserAgent { get; set; }

        public DateTimeOffset LastSeenAt { get; set; }

        public DateTimeOffset ExpiresAt { get; set; }

        public DateTimeOffset? LoggedOutAt { get; set; }

        public bool IsActive { get; set; } = true;
    }
}
