using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Data.Models;

public sealed class CompanyMobileAccessPolicy
{
    [Key, MaxLength(100)]
    public string CompanyCode { get; set; } = string.Empty;
    public bool RequireApprovedDevice { get; set; } = true;
    public int PolicyVersion { get; set; } = 1;
    public int UpdatedByAuthUserId { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
