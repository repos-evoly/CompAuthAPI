using System.Security.Cryptography;
using System.Text.Json;
using CompAuthApi.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Data.Context;
using Microsoft.AspNetCore.DataProtection;

namespace CompAuthApi.Endpoints;

public sealed class WebAuthenticatorReenrollmentEndpoints : IEndpoints
{
    internal const string BrowserKeyHeader = "X-Authenticator-Recovery-Browser";
    private static readonly TimeSpan ProofLifetime = TimeSpan.FromMinutes(5);

    public void RegisterEndpoints(WebApplication app) => app.MapPost("/api/auth/2fa-recovery/{action}", HandleAsync)
        .RequireRateLimiting("web-authenticator-recovery");

    internal static bool IsBrowserKey(string? key) => key is { Length: 64 } && key.All(char.IsAsciiHexDigit);

    internal static string IssueProof(IDataProtectionProvider protection, int userId, string login,
        string deviceId, string browserKey) =>
        ProofProtector(protection).Protect(JsonSerializer.Serialize(new PasswordProof(userId, login, deviceId,
            AuthenticatorRecoveryService.Hash(browserKey))), ProofLifetime);

    private static ITimeLimitedDataProtector ProofProtector(IDataProtectionProvider protection) =>
        protection.CreateProtector("CompAuth.WebAuthenticatorReenrollment.PasswordProof.v1").ToTimeLimitedDataProtector();

    internal static async Task<IResult> HandleAsync(string action, WebRecoveryRequest request, HttpContext context,
        CompAuthApiDbContext db, IDataProtectionProvider protection)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (action is not ("request" or "status" or "setup" or "complete")) return Results.NotFound();
        var browserKey = context.Request.Headers[BrowserKeyHeader].ToString();
        var deviceId = context.Request.Cookies["authDeviceId"];
        if (!IsBrowserKey(browserKey) || !AuthEndpoints.IsSafeToken(deviceId) ||
            request.Proof is not { Length: > 0 and <= 2048 })
            return Results.Problem(statusCode: 401);

        PasswordProof? proof;
        try { proof = JsonSerializer.Deserialize<PasswordProof>(ProofProtector(protection).Unprotect(request.Proof)); }
        catch (CryptographicException) { return Results.Problem(statusCode: 401); }
        catch (JsonException) { return Results.Problem(statusCode: 401); }
        if (proof is null || proof.UserId <= 0 || proof.DeviceId != deviceId ||
            proof.BrowserKeyHash != AuthenticatorRecoveryService.Hash(browserKey))
            return Results.Problem(statusCode: 401);

        var recovery = new AuthenticatorRecoveryService(db);
        var setupProtector = protection.CreateProtector("CompAuth.AuthenticatorReenrollment.v1");
        var result = action switch
        {
            "request" => await recovery.RequestReenrollmentAsync(proof.UserId, proof.Login, proof.DeviceId,
                browserKey, keyAuthorizedForNewRequest: true),
            "status" => await recovery.ReadReenrollmentAsync(proof.UserId, proof.Login, proof.DeviceId, browserKey),
            "setup" => await recovery.PrepareReenrollmentAsync(proof.UserId, proof.Login, proof.DeviceId, browserKey, setupProtector),
            _ => await recovery.CompleteReenrollmentAsync(proof.UserId, proof.Login, proof.DeviceId, browserKey, request.Code, setupProtector)
        };

        if (result.HttpStatus != 200)
            return Results.Problem(statusCode: result.HttpStatus,
                extensions: new Dictionary<string, object?> { ["code"] = result.Code });
        if (result.Setup is not null) return AuthEndpoints.SetupResponse(result.Setup);
        return Results.Ok(new { result.Status, result.RequestId, result.AlreadyRequested, result.CanContinue });
    }

    public sealed record WebRecoveryRequest(string? Proof, string? Code);
    private sealed record PasswordProof(int UserId, string Login, string DeviceId, string BrowserKeyHash);
}
