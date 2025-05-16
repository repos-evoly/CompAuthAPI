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
        public bool IsRecaptchaEnabled { get; set; }
        public string? RecaptchaSiteKey { get; set; }  // Nullable
        public string? RecaptchaSecretKey { get; set; } // Nullable
        public string? Url { get; set; } // Nullable
        public string? Date { get; set; } // Nullable
    }
}
