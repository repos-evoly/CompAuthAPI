using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Data.Models;

public enum AuthenticatorReenrollmentStatus { Requested, Approved, Completed, Cancelled }

public sealed class AuthenticatorReenrollment
{
    public Guid Id { get; set; }
    public int UserId { get; set; }
    public User User { get; set; } = null!;
    [MaxLength(64)] public string DeviceId { get; set; } = "";
    [MaxLength(64)] public string RequestKeyHash { get; set; } = "";
    [MaxLength(64)] public string PasswordFingerprint { get; set; } = "";
    [MaxLength(64)] public string PreviousSecretFingerprint { get; set; } = "";
    public string? ProtectedSetupSecret { get; set; }
    public AuthenticatorReenrollmentStatus Status { get; set; }
    public DateTimeOffset RequestedAt { get; set; }
    public DateTimeOffset? ClosedAt { get; set; }
    public int? ApprovedByAuthUserId { get; set; }
    public DateTimeOffset? ApprovedAt { get; set; }
    public int? CancelledByAuthUserId { get; set; }
    public DateTimeOffset? CancelledAt { get; set; }
}
