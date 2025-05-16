using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Core.Dtos
{
    public class EnableTwoFactorDto
    {
        [Required]
        public string? Email { get; set; }
    }
}
