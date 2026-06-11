using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CompAuthApi.Data.Models
{
    [Table("GeoFenceSettings")]
    public class GeoFenceSetting : Auditable
    {
        [Key]
        public int Id { get; set; }

        [DefaultValue(true)]
        public bool IsEnabled { get; set; } = true;

        public int DefaultCountrySwitchCooldownMinutes { get; set; } = 120;

        [DefaultValue(false)]
        public bool DebugExposeClientIp { get; set; } = false;

        [DefaultValue(true)]
        public bool BypassPrivateIps { get; set; } = true;

        [DefaultValue(false)]
        public bool BlockUnknownCountries { get; set; } = false;
    }
}
