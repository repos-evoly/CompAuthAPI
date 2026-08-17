using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models;

[Table("DeviceChallenges")]
[Index(nameof(MobileDeviceId), nameof(Purpose), nameof(ExpiresAt))]
public sealed class DeviceChallenge
{
    [Key]
    public Guid Id { get; set; }

    public Guid MobileDeviceId { get; set; }
    public MobileDevice MobileDevice { get; set; } = null!;

    public Guid? ActivationCodeId { get; set; }
    public DeviceActivationCode? ActivationCode { get; set; }

    [Required, MaxLength(32)]
    public string Purpose { get; set; } = string.Empty;

    [Required, MaxLength(128)]
    public string Nonce { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
