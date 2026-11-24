using System.Net;
using System.Security.Claims;
using CompAuthApi.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Data.Context;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Endpoints;

public sealed class AdminAuthenticatorReenrollmentEndpoints : IEndpoints
{
    public void RegisterEndpoints(WebApplication app)
    {
        var admin = app.MapGroup("/api/admin/authenticator-recovery")
            .RequireAuthorization("requireAuthUser").RequireAuthorization(policy => policy.RequireRole("Admin", "SuperAdmin"));
        admin.MapPost("/directory", ReadDirectoryAsync);
        admin.MapGet("/username", FindUsernameAsync);
        admin.MapPost("/{authUserId:int}/{requestId:guid}/approve", ApproveAsync);
        admin.MapPost("/{authUserId:int}/{requestId:guid}/cancel", CancelAsync);
    }

    private static async Task<IResult> ReadDirectoryAsync(DirectoryRequest request, HttpContext context,
        CompAuthApiDbContext db, IHttpClientFactory clients, IConfiguration config)
    {
        if (request.AuthUserIds is not { Length: > 0 and <= 50 } || request.AuthUserIds.Any(id => id <= 0))
            return Results.BadRequest();
        var permission = await CheckBankAccessAsync(context, clients, config, request.AuthUserIds);
        if (permission is not null) return permission;
        var users = await db.Users.AsNoTracking().Where(user => request.AuthUserIds.Contains(user.Id))
            .Select(user => new { user.Id, user.Username, user.Email }).ToListAsync(context.RequestAborted);
        var requests = await db.AuthenticatorReenrollments.AsNoTracking()
            .Where(item => request.AuthUserIds.Contains(item.UserId))
            .GroupBy(item => item.UserId)
            .Select(group => group.OrderBy(item => item.ClosedAt != null)
                .ThenByDescending(item => item.RequestedAt).ThenByDescending(item => item.Id).First())
            .ToListAsync(context.RequestAborted);
        var byUser = requests.ToDictionary(item => item.UserId);
        return Results.Ok(users.Select(user =>
        {
            var recovery = byUser.GetValueOrDefault(user.Id);
            return new
            {
                authUserId = user.Id, user.Username, user.Email, requestId = recovery?.Id,
                status = recovery?.Status.ToString().ToLowerInvariant() ?? "none",
                requestedAt = recovery?.RequestedAt, approvedAt = recovery?.ApprovedAt
            };
        }));
    }

    private static async Task<IResult> FindUsernameAsync(string username, HttpContext context,
        CompAuthApiDbContext db, IHttpClientFactory clients, IConfiguration config)
    {
        var permission = await CheckBankAccessAsync(context, clients, config);
        if (permission is not null) return permission;
        if (string.IsNullOrWhiteSpace(username) || username.Length > 150) return Results.BadRequest();
        var userId = await db.Users.AsNoTracking().Where(user => user.Username == username.Trim())
            .Select(user => (int?)user.Id).FirstOrDefaultAsync(context.RequestAborted);
        if (userId.HasValue)
        {
            var targetPermission = await CheckBankAccessAsync(context, clients, config, new[] { userId.Value });
            if (targetPermission is IStatusCodeHttpResult { StatusCode: 403 }) userId = null;
            else if (targetPermission is not null) return targetPermission;
        }
        return Results.Ok(new { authUserId = userId });
    }

    private static Task<IResult> ApproveAsync(int authUserId, Guid requestId, HttpContext context,
        CompAuthApiDbContext db, IHttpClientFactory clients, IConfiguration config) =>
        SetDecisionAsync(authUserId, requestId, context, db, clients, config, true);

    private static Task<IResult> CancelAsync(int authUserId, Guid requestId, HttpContext context,
        CompAuthApiDbContext db, IHttpClientFactory clients, IConfiguration config) =>
        SetDecisionAsync(authUserId, requestId, context, db, clients, config, false);

    private static async Task<IResult> SetDecisionAsync(int authUserId, Guid requestId, HttpContext context,
        CompAuthApiDbContext db, IHttpClientFactory clients, IConfiguration config, bool approve)
    {
        var permission = await CheckBankAccessAsync(context, clients, config, new[] { authUserId });
        if (permission is not null) return permission;
        if (!int.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier) ??
                          context.User.FindFirstValue("nameid"), out var staffId))
            return Results.Unauthorized();
        var result = await new AuthenticatorRecoveryService(db)
            .SetReenrollmentDecisionAsync(authUserId, requestId, staffId, approve);
        return result.HttpStatus == 200 ? Results.Ok(new { result.Status, result.RequestId }) :
            Results.Problem(statusCode: result.HttpStatus, extensions: new Dictionary<string, object?> { ["code"] = result.Code });
    }

    private static async Task<IResult?> CheckBankAccessAsync(HttpContext context,
        IHttpClientFactory clients, IConfiguration config, int[]? targetAuthUserIds = null)
    {
        context.Response.Headers.CacheControl = "no-store";
        var configured = config["AuthenticatorReenrollment:CompGateBaseUrl"]?.TrimEnd('/');
        if (!Uri.TryCreate(configured + "/", UriKind.Absolute, out var baseUri) ||
            baseUri.Scheme is not ("http" or "https"))
            return Results.Problem(statusCode: 503, detail: "The bank recovery directory is unavailable.");

        var path = "api/admin/company-users/access";
        if (targetAuthUserIds is not null)
            path += "?" + string.Join("&", targetAuthUserIds.Distinct().Select(id => $"targetAuthUserId={id}"));
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, path));
        var authorization = context.Request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return Results.Unauthorized();
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        using var client = clients.CreateClient("AuthenticatorReenrollmentBank");
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
            return response.StatusCode == HttpStatusCode.NoContent ? null
                : Results.StatusCode((int)response.StatusCode >= 500 ? 503 : 403);
        }
        catch (HttpRequestException) { return Results.StatusCode(503); }
        catch (OperationCanceledException) when (!context.RequestAborted.IsCancellationRequested) { return Results.StatusCode(503); }
    }

    public sealed record DirectoryRequest(int[] AuthUserIds);
}
