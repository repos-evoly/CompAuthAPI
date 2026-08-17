using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models;

[Table("DeviceSessions")]
[Index(nameof(TokenHash), IsUnique = true)]
[Index(nameof(MobileDeviceId), nameof(RevokedAt))]
[Index(nameof(CompAuthSessionId), nameof(RevokedAt))]
public sealed class DeviceSession
{
    [Key]
    public Guid Id { get; set; }

    public Guid MobileDeviceId { get; set; }
    public MobileDevice MobileDevice { get; set; } = null!;

    public int AuthUserId { get; set; }

    [Required, MaxLength(64)]
    public string CompAuthSessionId { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string TokenHash { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
}
