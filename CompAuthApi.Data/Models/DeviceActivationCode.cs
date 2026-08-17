using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models;

[Table("DeviceActivationCodes")]
[Index(nameof(CodeHash), IsUnique = true)]
[Index(nameof(CompanyCode), nameof(ExpiresAt))]
public sealed class DeviceActivationCode
{
    [Key]
    public Guid Id { get; set; }

    [Required, MaxLength(64)]
    public string CodeHash { get; set; } = string.Empty;

    public int TargetAuthUserId { get; set; }

    [Required, MaxLength(64)]
    public string LoginHash { get; set; } = string.Empty;

    public int CreatedByAuthUserId { get; set; }

    [Required, MaxLength(32)]
    public string CompanyCode { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
    public Guid? UsedByDeviceId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
