using System.Security.Claims;
using CompAuthApi.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Devices;
using Microsoft.AspNetCore.RateLimiting;

namespace CompAuthApi.Endpoints;

public sealed class MobileDeviceEndpoints : IEndpoints
{
    public void RegisterEndpoints(WebApplication app)
    {
        var devices = app.MapGroup("/api/mobile-devices")
            .WithTags("Mobile Device Authentication")
            .RequireAuthorization(ServiceAuthenticationDefaults.RequireMobileBffServicePolicy);

        devices.MapPost("/enrollment/challenge", EnrollmentChallenge)
            .RequireRateLimiting("mobile-auth-sensitive");
        devices.MapPost("/enroll", Enroll)
            .RequireRateLimiting("mobile-auth-sensitive");
        devices.MapPost("/login-challenge", LoginChallenge)
            .RequireRateLimiting("mobile-auth-sensitive");
        devices.MapGet("/status", Status)
            .RequireRateLimiting("mobile-auth-standard");
        devices.MapPost("/sessions/validate", ValidateSession)
            .RequireRateLimiting("mobile-auth-standard");
        devices.MapPost("/sessions/touch", TouchSession)
            .RequireRateLimiting("mobile-auth-standard");
        devices.MapPost("/sessions/revoke", RevokeSession)
            .RequireRateLimiting("mobile-auth-standard");

        var administration = devices.MapGroup("/admin")
            .RequireAuthorization(
                ServiceAuthenticationDefaults.RequireCompanyUserAndMobileBffServicePolicy);
        administration.MapPost("/activation-codes", CreateActivationCode)
            .RequireRateLimiting("mobile-auth-sensitive");
        administration.MapGet("/devices", ListDevices)
            .RequireRateLimiting("mobile-auth-standard");
        administration.MapPost("/devices/{deviceId:guid}/approve", Approve)
            .RequireRateLimiting("mobile-auth-sensitive");
        administration.MapPost("/devices/{deviceId:guid}/revoke", Revoke)
            .RequireRateLimiting("mobile-auth-sensitive");
    }

    private static Task<IResult> EnrollmentChallenge(
        DeviceEnrollmentChallengeRequest request,
        IDeviceSecurityService service,
        CancellationToken cancellationToken) =>
        ExecuteAsync(() => service.CreateEnrollmentChallengeAsync(request, cancellationToken));

    private static Task<IResult> Enroll(
        DeviceEnrollmentRequest request,
        IDeviceSecurityService service,
        CancellationToken cancellationToken) =>
        ExecuteAsync(() => service.CompleteEnrollmentAsync(request, cancellationToken));

    private static Task<IResult> LoginChallenge(
        DeviceLoginChallengeRequest request,
        IDeviceSecurityService service,
        CancellationToken cancellationToken) =>
        ExecuteAsync(() => service.CreateLoginChallengeAsync(request, cancellationToken));

    private static Task<IResult> Status(
        string installationId,
        IDeviceSecurityService service,
        CancellationToken cancellationToken) =>
        ExecuteAsync(() => service.GetStatusAsync(installationId, cancellationToken));

    private static Task<IResult> ValidateSession(
        ValidateDeviceSessionRequest request,
        IDeviceSecurityService service,
        CancellationToken cancellationToken) =>
        ExecuteAsync(() => service.ValidateSessionAsync(
            request.Token,
            request.ExpectedAuthUserId,
            cancellationToken));

    private static async Task<IResult> TouchSession(
        DeviceSessionMutationRequest request,
        IDeviceSecurityService service,
        CancellationToken cancellationToken)
    {
        try
        {
            await service.TouchSessionAsync(request.SessionId, cancellationToken);
            return Results.Ok(new { success = true });
        }
        catch (Exception exception)
        {
            return MapException(exception);
        }
    }

    private static async Task<IResult> RevokeSession(
        DeviceSessionMutationRequest request,
        IDeviceSecurityService service,
        CancellationToken cancellationToken)
    {
        try
        {
            await service.RevokeSessionAsync(request.SessionId, cancellationToken);
            return Results.Ok(new { success = true });
        }
        catch (Exception exception)
        {
            return MapException(exception);
        }
    }

    private static Task<IResult> CreateActivationCode(
        CreateDeviceActivationCodeRequest request,
        HttpContext context,
        IDeviceAdministrationService service,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserId(context.User, out var administratorId))
        {
            return Task.FromResult<IResult>(Problem(
                401,
                "user_authentication_required",
                "A valid user session is required."));
        }

        return ExecuteAsync(() => service.CreateActivationCodeAsync(
            administratorId,
            request,
            cancellationToken));
    }

    private static Task<IResult> ListDevices(
        string companyCode,
        int page,
        int limit,
        string? status,
        IDeviceAdministrationService service,
        CancellationToken cancellationToken) =>
        ExecuteAsync(() => service.GetDevicesAsync(
            companyCode,
            page,
            limit,
            status,
            cancellationToken));

    private static Task<IResult> Approve(
        Guid deviceId,
        string companyCode,
        HttpContext context,
        IDeviceAdministrationService service,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserId(context.User, out var administratorId))
        {
            return Task.FromResult<IResult>(Problem(
                401,
                "user_authentication_required",
                "A valid user session is required."));
        }

        return ExecuteAsync(() => service.ApproveAsync(
            administratorId,
            deviceId,
            companyCode,
            cancellationToken));
    }

    private static Task<IResult> Revoke(
        Guid deviceId,
        string companyCode,
        HttpContext context,
        IDeviceAdministrationService service,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserId(context.User, out var administratorId))
        {
            return Task.FromResult<IResult>(Problem(
                401,
                "user_authentication_required",
                "A valid user session is required."));
        }

        return ExecuteAsync(() => service.RevokeAsync(
            administratorId,
            deviceId,
            companyCode,
            cancellationToken));
    }

    private static async Task<IResult> ExecuteAsync<T>(Func<Task<T>> action)
    {
        try
        {
            return Results.Ok(await action());
        }
        catch (Exception exception)
        {
            return MapException(exception);
        }
    }

    private static IResult MapException(Exception exception) => exception switch
    {
        InvalidActivationCodeException => Problem(400, "invalid_activation_code", "The activation code is invalid or expired."),
        DeviceEnrollmentConflictException => Problem(409, "device_already_registered", "This installation is already registered."),
        InvalidDevicePublicKeyException => Problem(400, "invalid_device_public_key", "The device public key is invalid."),
        InvalidDeviceChallengeException => Problem(400, "invalid_device_challenge", "The device challenge is invalid or expired."),
        InvalidDeviceProofException => Problem(401, "invalid_device_proof", "Device ownership could not be verified."),
        DeviceNotApprovedException => Problem(403, "device_not_approved", "This device is not approved for mobile access."),
        InvalidDeviceSessionException => Problem(401, "invalid_device_session", "The device session is invalid or expired."),
        DeviceTargetUserInvalidException => Problem(403, "device_target_user_invalid", "The target user is not eligible for mobile access."),
        InvalidDeviceStatusException => Problem(400, "invalid_device_status", "The device status filter is invalid."),
        DeviceNotFoundException => Problem(404, "device_not_found", "The device was not found."),
        DeviceStateConflictException => Problem(409, "device_state_conflict", "The device cannot be changed from its current state."),
        DeviceAttestationUnavailableException => Problem(503, "device_attestation_unavailable", "Device attestation is unavailable."),
        DeviceSecurityDisabledException => Problem(503, "device_security_disabled", "Approved-device security is disabled."),
        _ => throw exception
    };

    private static bool TryGetUserId(ClaimsPrincipal principal, out int userId) =>
        int.TryParse(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out userId) &&
        userId > 0;

    private static IResult Problem(int status, string code, string detail) =>
        Results.Problem(
            statusCode: status,
            detail: detail,
            extensions: new Dictionary<string, object?> { ["code"] = code });
}

public sealed record ValidateDeviceSessionRequest(string Token, int? ExpectedAuthUserId);
public sealed record DeviceSessionMutationRequest(Guid SessionId);
