using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models
{
    [Table("GeoFenceCountryRules")]
    [Index(nameof(FromCountryCode), nameof(ToCountryCode), nameof(IsActive), Name = "IX_GeoFenceCountryRules_CountryPair")]
    public class GeoFenceCountryRule : Auditable
    {
        [Key]
        public int Id { get; set; }

        [Required, MaxLength(2)]
        public string FromCountryCode { get; set; } = string.Empty;

        [Required, MaxLength(2)]
        public string ToCountryCode { get; set; } = string.Empty;

        public int CooldownMinutes { get; set; }

        [DefaultValue(true)]
        public bool IsAllowed { get; set; } = true;

        [DefaultValue(true)]
        public bool IsActive { get; set; } = true;

        [MaxLength(256)]
        public string? Description { get; set; }
    }
}
