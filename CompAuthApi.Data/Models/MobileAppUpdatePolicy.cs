using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Data.Models;

public sealed class MobileAppUpdatePolicy
{
    [Key, MaxLength(7)] public string Platform { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    [MaxLength(32)] public string MinimumVersion { get; set; } = "1.0.0";
    [MaxLength(32)] public string MinimumBuild { get; set; } = "0";
    [MaxLength(512)] public string StoreUrl { get; set; } = string.Empty;
    [MaxLength(500)] public string MessageEn { get; set; } = "Please update the app to continue.";
    [MaxLength(500)] public string MessageAr { get; set; } = "يرجى تحديث التطبيق للمتابعة.";
    public int Revision { get; set; } = 1;
    [MaxLength(128)] public string? UpdatedBy { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}
