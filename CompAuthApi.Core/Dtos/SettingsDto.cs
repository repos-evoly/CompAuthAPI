namespace CompAuthApi.Core.Dtos
{
    public class SettingsDto
    {
        public bool IsTwoFactorAuthEnabled { get; set; }
        public bool IsRecaptchaEnabled { get; set; }
        public string? Url { get; set; }
        public string? Date { get; set; }
    }

    public class EditSettingsDto
    {
        public bool IsTwoFactorAuthEnabled { get; set; }
        public bool IsRecaptchaEnabled { get; set; }
        public string? Url { get; set; }
    }
}
