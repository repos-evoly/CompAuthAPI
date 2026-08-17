using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models;

public enum DeviceRegistrationStatus
{
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Revoked = 3
}

[Table("MobileDevices")]
[Index(nameof(InstallationId), IsUnique = true)]
[Index(nameof(CompanyCode), nameof(Status))]
[Index(nameof(TargetAuthUserId), nameof(Status))]
public sealed class MobileDevice
{
    [Key]
    public Guid Id { get; set; }

    [Required, MaxLength(64)]
    public string InstallationId { get; set; } = string.Empty;

    public int TargetAuthUserId { get; set; }

    [Required, MaxLength(64)]
    public string LoginHash { get; set; } = string.Empty;

    [MaxLength(32)]
    public string? CompanyCode { get; set; }

    [Required, MaxLength(16)]
    public string Platform { get; set; } = string.Empty;

    [MaxLength(32)]
    public string? AppVersion { get; set; }

    [Required, MaxLength(32)]
    public string KeyAlgorithm { get; set; } = string.Empty;

    [Required, MaxLength(4096)]
    public string PublicKeyPem { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string PublicKeyFingerprint { get; set; } = string.Empty;

    [MaxLength(32)]
    public string? AttestationProvider { get; set; }

    [MaxLength(32)]
    public string? AttestationStatus { get; set; }

    public DeviceRegistrationStatus Status { get; set; } =
        DeviceRegistrationStatus.Pending;

    public DateTimeOffset? ProofVerifiedAt { get; set; }
    public DateTimeOffset? ApprovedAt { get; set; }
    public int? ApprovedByAuthUserId { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public int? RevokedByAuthUserId { get; set; }
    public DateTimeOffset? LastSeenAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public ICollection<DeviceChallenge> Challenges { get; set; } = [];
    public ICollection<DeviceSession> DeviceSessions { get; set; } = [];
    public ICollection<DeviceLoginGrant> LoginGrants { get; set; } = [];
    public MobilePushToken? PushToken { get; set; }
}
