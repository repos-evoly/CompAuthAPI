using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Data.Models;

public sealed class MobileAppMaintenancePolicy
{
    [Key] public int Id { get; set; } = 1;
    public bool Enabled { get; set; }
    [MaxLength(500)] public string MessageEn { get; set; } = "The app is temporarily unavailable for maintenance. Please try again later.";
    [MaxLength(500)] public string MessageAr { get; set; } = "التطبيق غير متاح مؤقتاً للصيانة. يرجى المحاولة لاحقاً.";
    public int Revision { get; set; } = 1;
    [MaxLength(128)] public string? UpdatedBy { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}
