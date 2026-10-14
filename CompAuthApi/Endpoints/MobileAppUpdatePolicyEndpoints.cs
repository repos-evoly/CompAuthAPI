using System.Security.Claims;
using System.Text.RegularExpressions;
using CompAuthApi.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Endpoints;

public sealed class MobileAppUpdatePolicyEndpoints : IEndpoints
{
    public void RegisterEndpoints(WebApplication app)
    {
        var admin = app.MapGroup("/api/settings/mobile-app-updates")
            .RequireAuthorization("requireAuthUser")
            .RequireAuthorization(policy => policy.RequireRole("Admin"));
        admin.MapGet("", ReadAdmin);
        admin.MapPut("/{platform}", Update);
        app.MapGet("/api/mobile-auth/app-updates", Read)
            .RequireAuthorization(ServiceAuthenticationDefaults.RequireMobileBffServicePolicy);
    }

    internal static async Task<IResult> Read(CompAuthApiDbContext db, HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        var policies = await db.MobileAppUpdatePolicies.AsNoTracking().OrderBy(p => p.Platform)
            .ToListAsync(context.RequestAborted);
        return Results.Ok(policies.Select(p => new
        {
            p.Platform, p.Enabled, p.MinimumVersion, p.MinimumBuild, p.StoreUrl,
            p.MessageEn, p.MessageAr, p.Revision
        }));
    }

    internal static async Task<IResult> ReadAdmin(CompAuthApiDbContext db, HttpContext context)
    {
        if (!context.User.IsInRole("Admin")) return Results.StatusCode(403);
        context.Response.Headers.CacheControl = "no-store";
        return Results.Ok(await db.MobileAppUpdatePolicies.AsNoTracking().OrderBy(p => p.Platform)
            .ToListAsync(context.RequestAborted));
    }

    internal static async Task<IResult> Update(string platform, UpdateMobileAppPolicy request,
        CompAuthApiDbContext db, HttpContext context, ILogger<MobileAppUpdatePolicyEndpoints> logger)
    {
        if (!context.User.IsInRole("Admin")) return Results.StatusCode(403);
        var actor = context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? context.User.FindFirstValue("nameid");
        if (string.IsNullOrWhiteSpace(actor) || actor.Length > 128) return Results.Unauthorized();
        if (platform is not ("android" or "ios") || request.Enabled is null || request.Revision is null or < 1 ||
            !ValidVersion(request.MinimumVersion, 3, 3) || !ValidVersion(request.MinimumBuild, 1, 3) ||
            request.MessageEn is null || request.MessageAr is null ||
            string.IsNullOrWhiteSpace(request.MessageEn) || string.IsNullOrWhiteSpace(request.MessageAr) ||
            request.MessageEn.Length > 500 || request.MessageAr.Length > 500 ||
            request.StoreUrl is null || request.StoreUrl.Length > 512 ||
            (request.StoreUrl.Length > 0 && !ValidStoreUrl(platform, request.StoreUrl)) ||
            (request.Enabled.Value && !ValidStoreUrl(platform, request.StoreUrl)))
            return Results.BadRequest(new { detail = "Supply a platform, version (X.Y.Z), numeric build, official store URL, both messages, and current revision. An enabled policy requires a store URL." });
        var now = DateTimeOffset.UtcNow;
        var updated = await db.MobileAppUpdatePolicies
            .Where(p => p.Platform == platform && p.Revision == request.Revision)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(p => p.Enabled, request.Enabled.Value)
                .SetProperty(p => p.MinimumVersion, request.MinimumVersion!)
                .SetProperty(p => p.MinimumBuild, request.MinimumBuild!)
                .SetProperty(p => p.StoreUrl, request.StoreUrl!)
                .SetProperty(p => p.MessageEn, request.MessageEn.Trim())
                .SetProperty(p => p.MessageAr, request.MessageAr.Trim())
                .SetProperty(p => p.Revision, p => p.Revision + 1)
                .SetProperty(p => p.UpdatedBy, actor)
                .SetProperty(p => p.UpdatedAt, now), context.RequestAborted);
        if (updated != 1) return Results.Conflict(new { detail = "The update policy changed. Reload before saving." });
        logger.LogInformation("Mobile update policy for {Platform} changed by {Actor}; revision {Revision}.", platform, actor, request.Revision + 1);
        return await ReadAdmin(db, context);
    }

    internal static bool ValidVersion(string? value, int minimumParts, int maximumParts)
    {
        if (value is null || value.Length > 32 || !Regex.IsMatch(value, @"^[0-9]{1,9}(\.[0-9]{1,9}){0,2}$")) return false;
        var count = value.Split('.').Length;
        return count >= minimumParts && count <= maximumParts;
    }

    internal static bool ValidStoreUrl(string platform, string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            !string.IsNullOrEmpty(uri.UserInfo) || !uri.IsDefaultPort || !string.IsNullOrEmpty(uri.Fragment)) return false;
        if (platform == "android")
            return uri.Host == "play.google.com" && uri.AbsolutePath == "/store/apps/details" &&
                QueryHelpers.ParseQuery(uri.Query).TryGetValue("id", out var id) &&
                id.Count == 1 && id[0] == "com.bcd.companygateway";
        return platform == "ios" && uri.Host == "apps.apple.com" &&
            Regex.IsMatch(uri.AbsolutePath, @"^/(?:[a-z]{2}/)?app/(?:[^/]+/)?id[0-9]+/?$");
    }
}

public sealed record UpdateMobileAppPolicy(bool? Enabled, string? MinimumVersion, string? MinimumBuild,
    string? StoreUrl, string? MessageEn, string? MessageAr, int? Revision);
