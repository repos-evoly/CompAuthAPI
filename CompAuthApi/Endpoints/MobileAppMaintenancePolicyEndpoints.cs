using System.Security.Claims;
using CompAuthApi.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Data.Context;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Endpoints;

public sealed class MobileAppMaintenancePolicyEndpoints : IEndpoints
{
    public void RegisterEndpoints(WebApplication app)
    {
        var admin = app.MapGroup("/api/settings/mobile-app-maintenance")
            .RequireAuthorization("requireAuthUser")
            .RequireAuthorization(policy => policy.RequireRole("Admin"));
        admin.MapGet("", ReadAdmin);
        admin.MapPut("", Update);
        app.MapGet("/api/mobile-auth/app-maintenance", Read)
            .RequireAuthorization(ServiceAuthenticationDefaults.RequireMobileBffServicePolicy);
    }

    internal static async Task<IResult> Read(CompAuthApiDbContext db, HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        var policy = await db.MobileAppMaintenancePolicies.AsNoTracking().SingleAsync(context.RequestAborted);
        return Results.Ok(new { policy.Enabled, policy.MessageEn, policy.MessageAr, policy.Revision });
    }

    internal static async Task<IResult> ReadAdmin(CompAuthApiDbContext db, HttpContext context)
    {
        if (!context.User.IsInRole("Admin")) return Results.StatusCode(403);
        context.Response.Headers.CacheControl = "no-store";
        return Results.Ok(await db.MobileAppMaintenancePolicies.AsNoTracking().SingleAsync(context.RequestAborted));
    }

    internal static async Task<IResult> Update(UpdateMobileAppMaintenancePolicy request,
        CompAuthApiDbContext db, HttpContext context, ILogger<MobileAppMaintenancePolicyEndpoints> logger)
    {
        if (!context.User.IsInRole("Admin")) return Results.StatusCode(403);
        var actor = context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? context.User.FindFirstValue("nameid");
        if (string.IsNullOrWhiteSpace(actor) || actor.Length > 128) return Results.Unauthorized();
        if (request.Enabled is null || request.Revision is null or < 1 ||
            string.IsNullOrWhiteSpace(request.MessageEn) || string.IsNullOrWhiteSpace(request.MessageAr) ||
            request.MessageEn.Length > 500 || request.MessageAr.Length > 500)
            return Results.BadRequest(new { detail = "Supply maintenance on/off, both messages (1–500 characters), and the current revision." });
        var now = DateTimeOffset.UtcNow;
        var updated = await db.MobileAppMaintenancePolicies
            .Where(p => p.Id == 1 && p.Revision == request.Revision)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(p => p.Enabled, request.Enabled.Value)
                .SetProperty(p => p.MessageEn, request.MessageEn.Trim())
                .SetProperty(p => p.MessageAr, request.MessageAr.Trim())
                .SetProperty(p => p.Revision, p => p.Revision + 1)
                .SetProperty(p => p.UpdatedBy, actor)
                .SetProperty(p => p.UpdatedAt, now), context.RequestAborted);
        if (updated != 1) return Results.Conflict(new { detail = "The maintenance policy changed. Reload before saving." });
        logger.LogInformation("Mobile maintenance changed to {Enabled} by {Actor}; revision {Revision}.", request.Enabled, actor, request.Revision + 1);
        return await ReadAdmin(db, context);
    }
}

public sealed record UpdateMobileAppMaintenancePolicy(bool? Enabled, string? MessageEn, string? MessageAr, int? Revision);
