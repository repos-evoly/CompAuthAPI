using System.ComponentModel;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CompAuthApi.Data.Models
{
    [Table("Role")]
    public class Role : Auditable
    {
        [Key]
        public int Id { get; set; }

        [MaxLength(100)]
        public string? TitleAR { get; set; }
        [Required]
        public string TitleLT { get; set; } = string.Empty;
        public ICollection<User>? Users { get; set; } = new List<User>();
    }
}
