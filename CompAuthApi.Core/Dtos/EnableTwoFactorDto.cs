using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Core.Dtos
{
    public class EnableTwoFactorDto
    {
        [Required]
        public string Login { get; set; } = "";
    }
}
