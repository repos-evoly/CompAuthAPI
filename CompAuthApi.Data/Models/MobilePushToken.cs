using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Data.Models;

[Table("MobilePushTokens")]
[Index(nameof(TokenHash), IsUnique = true)]
[Index(nameof(AuthUserId))]
public sealed class MobilePushToken
{
    [Key, ForeignKey(nameof(MobileDevice))]
    public Guid MobileDeviceId { get; set; }

    public int AuthUserId { get; set; }

    [Required, MaxLength(4096)]
    public string Token { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string TokenHash { get; set; } = string.Empty;

    [Required, MaxLength(16)]
    public string Platform { get; set; } = string.Empty;

    [MaxLength(32)]
    public string? AppVersion { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public MobileDevice MobileDevice { get; set; } = null!;
}
