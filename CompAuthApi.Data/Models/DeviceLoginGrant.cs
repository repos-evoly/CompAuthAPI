using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models;

[Table("DeviceLoginGrants")]
[Index(nameof(ChallengeTokenHash), IsUnique = true)]
[Index(nameof(MobileDeviceId), nameof(ExpiresAt))]
public sealed class DeviceLoginGrant
{
    [Key]
    public Guid Id { get; set; }

    public Guid MobileDeviceId { get; set; }
    public MobileDevice MobileDevice { get; set; } = null!;

    [Required, MaxLength(64)]
    public string ChallengeTokenHash { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string LoginHash { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
