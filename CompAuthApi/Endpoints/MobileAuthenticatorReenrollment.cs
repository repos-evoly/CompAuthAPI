using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Devices;
using CompAuthApi.Core.Dtos;
using CompAuthApi.Data.Context;
using Microsoft.AspNetCore.DataProtection;

namespace CompAuthApi.Endpoints;

public sealed partial class MobileAuthEndpoints
{
    private static void MapReenrollment(RouteGroupBuilder mobile)
    {
        var recovery = mobile.MapGroup("/2fa/recovery");
        recovery.MapPost("/request", RequestAuthenticatorRecovery).RequireRateLimiting("mobile-auth-sensitive");
        recovery.MapPost("/status", ReadAuthenticatorRecovery).RequireRateLimiting("mobile-auth-standard");
        recovery.MapPost("/setup", SetupRecoveredAuthenticator).RequireRateLimiting("mobile-auth-sensitive");
        recovery.MapPost("/complete", CompleteAuthenticatorRecovery).RequireRateLimiting("mobile-auth-sensitive");
    }

    private static Task<IResult> RequestAuthenticatorRecovery(AuthenticatorReenrollmentDto request,
        HttpContext context, CompAuthApiDbContext db, IMobileAuthChallengeService challenge, IDeviceSecurityService devices) =>
        RunReenrollmentAsync(request, context, challenge, devices, () =>
            new AuthenticatorRecoveryService(db).RequestReenrollmentAsync(
                request.AuthUserId, request.Login, request.DeviceId, request.ChallengeToken, request.RecoveryKey ?? ""));

    private static Task<IResult> ReadAuthenticatorRecovery(AuthenticatorReenrollmentDto request,
        HttpContext context, CompAuthApiDbContext db, IMobileAuthChallengeService challenge, IDeviceSecurityService devices) =>
        RunReenrollmentAsync(request, context, challenge, devices, () =>
            new AuthenticatorRecoveryService(db).ReadReenrollmentAsync(
                request.AuthUserId, request.Login, request.DeviceId, request.RecoveryKey));

    private static Task<IResult> SetupRecoveredAuthenticator(AuthenticatorReenrollmentDto request,
        HttpContext context, CompAuthApiDbContext db, IMobileAuthChallengeService challenge,
        IDeviceSecurityService devices, IDataProtectionProvider protection) =>
        RunReenrollmentAsync(request, context, challenge, devices, () =>
            new AuthenticatorRecoveryService(db).PrepareReenrollmentAsync(request.AuthUserId,
                request.Login, request.DeviceId, request.RecoveryKey ?? "", protection.CreateProtector("CompAuth.AuthenticatorReenrollment.v1")));

    private static Task<IResult> CompleteAuthenticatorRecovery(AuthenticatorReenrollmentDto request,
        HttpContext context, CompAuthApiDbContext db, IMobileAuthChallengeService challenge,
        IDeviceSecurityService devices, IDataProtectionProvider protection) =>
        RunReenrollmentAsync(request, context, challenge, devices, () =>
            new AuthenticatorRecoveryService(db).CompleteReenrollmentAsync(request.AuthUserId,
                request.Login, request.DeviceId, request.RecoveryKey ?? "", request.Token,
                protection.CreateProtector("CompAuth.AuthenticatorReenrollment.v1")));

    private static async Task<IResult> RunReenrollmentAsync(AuthenticatorReenrollmentDto request, HttpContext context,
        IMobileAuthChallengeService challenge, IDeviceSecurityService devices, Func<Task<ReenrollmentResult>> operation)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (request.AuthUserId <= 0 || request.Login is not { Length: > 0 and <= 256 } ||
            request.ChallengeToken is not { Length: > 0 and <= 4096 } ||
            request.RecoveryKey is { Length: > 4096 } || !IsSafeDeviceId(request.DeviceId) ||
            !challenge.Validate(request.ChallengeToken, request.Login, request.DeviceId, VerifyPurpose, request.AuthUserId))
            return InvalidChallenge();

        if ((await devices.GetLoginPolicyAsync(request.Login, context.RequestAborted)).RequireApprovedDevice)
        {
            try
            {
                await devices.AuthorizeTwoFactorAsync(request.Login, request.DeviceId,
                    request.ChallengeToken, context.RequestAborted);
            }
            catch (Exception exception) { return MapDeviceException(exception); }
        }
        var result = await operation();
        if (result.HttpStatus != 200)
            return Results.Problem(statusCode: result.HttpStatus,
                extensions: new Dictionary<string, object?> { ["code"] = result.Code });
        if (result.Setup is not null) return AuthEndpoints.SetupResponse(result.Setup);
        return Results.Ok(new { result.Status, result.RequestId, result.AlreadyRequested, result.CanContinue });
    }

    public sealed class AuthenticatorReenrollmentDto : MobileTwoFactorSetupDto
    {
        public int AuthUserId { get; set; }
        public string? RecoveryKey { get; set; }
        public string? Token { get; set; }
    }
}
