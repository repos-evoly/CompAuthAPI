using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CompAuthApi.Data.Models
{
    [Table("Settings")]
    public class Settings : Auditable
    {
        [Key]
        public int Id { get; set; }

        public bool IsTwoFactorAuthEnabled { get; set; }
        public bool RequireApprovedMobileDevice { get; set; } = true;
        public int MobileAccessPolicyVersion { get; set; } = 1;
        public string? MobileAccessPolicyUpdatedBy { get; set; }
        public DateTimeOffset? MobileAccessPolicyUpdatedAt { get; set; }
        public bool IsRecaptchaEnabled { get; set; }
        public string? RecaptchaSiteKey { get; set; }  // Nullable
        public string? RecaptchaSecretKey { get; set; } // Nullable
        public string? Url { get; set; } // Nullable
        public string? Date { get; set; } // Nullable
        public int MaxLoginAttempts {get; set; } = 5;
        public int LockTimeoutMinutes {get; set; } = 120;

    }
}
