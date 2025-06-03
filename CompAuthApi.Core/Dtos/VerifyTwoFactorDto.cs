using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Core.Dtos
{
    public class VerifyTwoFactorDto
    {
        [Required]
        public string Login { get; set; } = "";

        [Required]
        public required string Token { get; set; }
    }
}
