using System;
using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Core.Dtos
{
    public class RegisterDto
    {
        [Required]
        public required string FullNameAR { get; set; }

        [Required]
        public required string FullNameLT { get; set; }

        [Required, MaxLength(150)]
        public string Username { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        public required string Email { get; set; }

        [Required]
        [MinLength(6)]
        public required string Password { get; set; }

        [Required]
        public int RoleId { get; set; }


    }
}
