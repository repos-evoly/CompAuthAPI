using System.Security.Claims;
using CompAuthApi.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Devices;
using CompAuthApi.Data.Context;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Endpoints;

public sealed class MobileAccessPolicyEndpoints : IEndpoints
{
    public void RegisterEndpoints(WebApplication app)
    {
        // Keep POST compatible with the shipped mobile app; GET supports global-policy clients.
        app.MapMethods("/api/mobile-auth/policy", ["GET", "POST"], ReadPolicy)
            .RequireAuthorization(ServiceAuthenticationDefaults.RequireMobileBffServicePolicy)
            .RequireRateLimiting("mobile-auth-sensitive");
        var admin = app.MapGroup("/api/settings/mobile-access")
            .RequireAuthorization("requireAuthUser")
            .RequireAuthorization(policy => policy.RequireRole("Admin"));
        admin.MapGet("", Read);
        admin.MapPut("", Update);
    }

    private static async Task<IResult> ReadPolicy(CompAuthApiDbContext db, HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        return Results.Ok(await MobileAccessPolicyReader.ReadAsync(db, context.RequestAborted));
    }

    internal static Task<IResult> Read(CompAuthApiDbContext db, HttpContext context) =>
        context.User.IsInRole("Admin") ? ReadPolicy(db, context) : Task.FromResult(Results.StatusCode(403));

    internal static async Task<IResult> Update(UpdateMobileAccessPolicy request,
        CompAuthApiDbContext db, HttpContext context, ILogger<MobileAccessPolicyEndpoints> logger)
    {
        if (!context.User.IsInRole("Admin")) return Results.StatusCode(403);
        if (request.RequireApprovedDevice is null || request.PolicyVersion is null or < 1)
            return Results.BadRequest(new { detail = "An explicit approval setting and current policy version are required." });
        var actor = context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? context.User.FindFirstValue("nameid");
        if (string.IsNullOrWhiteSpace(actor)) return Results.Unauthorized();
        var now = DateTimeOffset.UtcNow;
        var changed = await db.Settings
            .Where(item => item.Id == 1 && item.MobileAccessPolicyVersion == request.PolicyVersion)
            .ExecuteUpdateAsync(update => update
                .SetProperty(item => item.RequireApprovedMobileDevice, request.RequireApprovedDevice.Value)
                .SetProperty(item => item.MobileAccessPolicyVersion, item => item.MobileAccessPolicyVersion + 1)
                .SetProperty(item => item.MobileAccessPolicyUpdatedBy, actor)
                .SetProperty(item => item.MobileAccessPolicyUpdatedAt, now), context.RequestAborted);
        if (changed != 1)
            return Results.Conflict(new { detail = "Settings changed or are unavailable. Reload before saving." });
        logger.LogWarning("Global mobile approval policy changed to {Required} by auth user {Actor}; version {Version}.",
            request.RequireApprovedDevice, actor, request.PolicyVersion + 1);
        return await ReadPolicy(db, context);
    }
}

public sealed record UpdateMobileAccessPolicy(bool? RequireApprovedDevice, int? PolicyVersion);
