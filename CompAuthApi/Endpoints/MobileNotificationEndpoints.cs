using System.Security.Claims;
using CompAuthApi.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Devices;
using Microsoft.AspNetCore.RateLimiting;

namespace CompAuthApi.Endpoints;

public sealed class MobileNotificationEndpoints : IEndpoints
{
    public void RegisterEndpoints(WebApplication app)
    {
        var notifications = app.MapGroup("/api/mobile-notifications")
            .WithTags("Mobile Push Notifications")
            .RequireAuthorization(ServiceAuthenticationDefaults.RequireMobileBffServicePolicy);

        var registrations = notifications.MapGroup("/push-token")
            .RequireAuthorization(
                ServiceAuthenticationDefaults.RequireCompanyUserAndMobileBffServicePolicy);
        registrations.MapPut("", Register)
            .RequireRateLimiting("mobile-auth-standard");
        registrations.MapDelete("/{deviceId:guid}", Remove)
            .RequireRateLimiting("mobile-auth-standard");
        registrations.MapGet("/status", Status)
            .RequireRateLimiting("mobile-auth-standard");

        notifications.MapPost("/targets/resolve", ResolveTargets)
            .RequireRateLimiting("mobile-auth-standard");
        notifications.MapPost("/push-token/invalidate", Invalidate)
            .RequireRateLimiting("mobile-auth-standard");
    }

    private static Task<IResult> Register(
        MobilePushTokenRegistrationRequest request,
        HttpContext context,
        IMobilePushTokenService service,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserId(context.User, out var authUserId))
        {
            return Task.FromResult<IResult>(UserRequired());
        }

        return ExecuteAsync(() => service.RegisterAsync(
            authUserId,
            request,
            cancellationToken));
    }

    private static Task<IResult> Remove(
        Guid deviceId,
        HttpContext context,
        IMobilePushTokenService service,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserId(context.User, out var authUserId))
        {
            return Task.FromResult<IResult>(UserRequired());
        }

        return ExecuteAsync(() => service.RemoveAsync(
            authUserId,
            deviceId,
            cancellationToken));
    }

    private static Task<IResult> Status(
        Guid deviceId,
        HttpContext context,
        IMobilePushTokenService service,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserId(context.User, out var authUserId))
        {
            return Task.FromResult<IResult>(UserRequired());
        }

        return ExecuteAsync(() => service.GetStatusAsync(
            authUserId,
            deviceId,
            cancellationToken));
    }

    private static Task<IResult> ResolveTargets(
        ResolveMobilePushTargetsRequest request,
        IMobilePushTokenService service,
        CancellationToken cancellationToken) =>
        ExecuteAsync(() => service.ResolveTargetsAsync(
            request.AuthUserIds ?? [],
            cancellationToken));

    private static Task<IResult> Invalidate(
        InvalidateMobilePushTokensRequest request,
        IMobilePushTokenService service,
        CancellationToken cancellationToken) =>
        ExecuteAsync(() => service.InvalidateAsync(
            request.DeviceIds ?? [],
            cancellationToken));

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
        InvalidPushTokenException => Problem(400, "invalid_push_token", "The Firebase registration token is invalid."),
        PushTokenPlatformMismatchException => Problem(400, "push_platform_mismatch", "The push platform does not match the approved device."),
        PushDeviceNotApprovedException => Problem(403, "push_device_not_approved", "The approved device is not eligible for notifications."),
        InvalidPushTargetRequestException => Problem(400, "invalid_push_targets", "The push-target request is invalid."),
        DeviceSecurityDisabledException => Problem(503, "device_security_disabled", "Approved-device security is disabled."),
        _ => throw exception
    };

    private static bool TryGetUserId(ClaimsPrincipal principal, out int userId) =>
        int.TryParse(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out userId) &&
        userId > 0;

    private static IResult UserRequired() =>
        Problem(401, "user_authentication_required", "A valid user session is required.");

    private static IResult Problem(int status, string code, string detail) =>
        Results.Problem(
            statusCode: status,
            detail: detail,
            extensions: new Dictionary<string, object?> { ["code"] = code });
}

public sealed record ResolveMobilePushTargetsRequest(
    IReadOnlyCollection<int>? AuthUserIds);

public sealed record InvalidateMobilePushTokensRequest(
    IReadOnlyCollection<Guid>? DeviceIds);
