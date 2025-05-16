using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Core.Dtos
{
    public class VerifyTwoFactorDto
    {
        [Required]
        public required string Email { get; set; }

        [Required]
        public required string Token { get; set; }
    }
}
