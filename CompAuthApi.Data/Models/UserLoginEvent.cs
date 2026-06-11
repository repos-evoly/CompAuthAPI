using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models
{
    [Table("UserLoginEvents")]
    [Index(nameof(UserId), nameof(IsSuccessful), nameof(EventAt), Name = "IX_UserLoginEvents_User_Success_Time")]
    public class UserLoginEvent : Auditable
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public int UserId { get; set; }

        public User? User { get; set; }

        [MaxLength(64)]
        public string? SessionId { get; set; }

        [MaxLength(64)]
        public string? IpAddress { get; set; }

        [MaxLength(512)]
        public string? XForwardedFor { get; set; }

        [MaxLength(64)]
        public string? RemoteIpAddress { get; set; }

        [MaxLength(2)]
        public string? CountryCode { get; set; }

        [MaxLength(128)]
        public string? CountryName { get; set; }

        public bool IsSuccessful { get; set; }

        [MaxLength(128)]
        public string? FailureCode { get; set; }

        [MaxLength(512)]
        public string? FailureReason { get; set; }

        public DateTimeOffset EventAt { get; set; }
    }
}
