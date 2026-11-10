using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models;

[Table("AuthenticatorActionGrants")]
[Index(nameof(UserId), nameof(Purpose), nameof(ExpiresUtc))]
public sealed class AuthenticatorActionGrant
{
    [Key, MaxLength(64)] public string TokenHash { get; set; } = "";
    public int UserId { get; set; }
    public User User { get; set; } = null!;
    [MaxLength(20)] public string Purpose { get; set; } = "";
    [MaxLength(64)] public string PasswordFingerprint { get; set; } = "";
    [MaxLength(64)] public string? SecretFingerprint { get; set; }
    public DateTime CreatedUtc { get; set; }
    public DateTime ExpiresUtc { get; set; }
    public DateTime? ConsumedUtc { get; set; }
}

[Table("AuthenticatorUsedSteps")]
[PrimaryKey(nameof(UserId), nameof(TimeStep))]
public sealed class AuthenticatorUsedStep
{
    public int UserId { get; set; }
    public User User { get; set; } = null!;
    public long TimeStep { get; set; }
    [MaxLength(20)] public string Purpose { get; set; } = "";
    public DateTime UsedUtc { get; set; }
}

[Table("PasswordRecoveryThrottles")]
public sealed class PasswordRecoveryThrottle
{
    [Key, MaxLength(64)] public string KeyHash { get; set; } = "";
    public DateTime WindowStartedUtc { get; set; }
    public int AttemptCount { get; set; }
}
