namespace CompAuthApi.Core.Dtos
{
    public class SettingsDto
    {
        public bool IsTwoFactorAuthEnabled { get; set; }
        public bool IsRecaptchaEnabled { get; set; }
        public string? RecaptchaSiteKey { get; set; }  // Nullable
        public string? RecaptchaSecretKey { get; set; } // Nullable
        public string? Url { get; set; }
        public string? Date { get; set; }
        public int MaxLoginAttempts {get; set; } 
        public int LockTimeoutMinutes {get; set; } 
    }

    public class EditSettingsDto
    {
        public bool IsTwoFactorAuthEnabled { get; set; }
        public bool IsRecaptchaEnabled { get; set; }
        public string? RecaptchaSiteKey { get; set; }  // Nullable
        public string? RecaptchaSecretKey { get; set; } // Nullable
        public string? Url { get; set; }
        public int MaxLoginAttempts {get; set; } 
        public int LockTimeoutMinutes {get; set; } 
    }
}
