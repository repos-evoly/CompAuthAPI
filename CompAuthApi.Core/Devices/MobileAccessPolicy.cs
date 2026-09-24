using CompAuthApi.Data.Context;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Core.Devices;

public sealed record MobileAccessPolicy(bool RequireApprovedDevice, int PolicyVersion);

public static class MobileAccessPolicyReader
{
    // Read on every authentication/validation boundary: no per-instance cache
    // that could let a session bypass a newly enabled policy.
    public static async Task<MobileAccessPolicy> ReadAsync(
        CompAuthApiDbContext db, CancellationToken cancellationToken) =>
        await db.Settings.AsNoTracking().Where(item => item.Id == 1)
            .Select(item => new MobileAccessPolicy(
                item.RequireApprovedMobileDevice, item.MobileAccessPolicyVersion))
            .SingleOrDefaultAsync(cancellationToken)
        ?? new MobileAccessPolicy(true, 1);

}
