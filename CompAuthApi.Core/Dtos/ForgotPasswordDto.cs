using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Core.Dtos
{
    public class ForgotPasswordDto
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
    }
}
