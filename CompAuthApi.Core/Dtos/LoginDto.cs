using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Core.Dtos
{
    public class LoginDto
    {
        [Required]
        public string Login { get; set; } = string.Empty;
    
        [Required]
        public string? Password { get; set; }

        public string? RecaptchaToken { get; set; }
    }
}
