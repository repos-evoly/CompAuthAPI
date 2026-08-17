using System.Text.Json;
using System.Text.Json.Nodes;
using CompAuthApi.Abstractions;
using CompAuthApi.Core.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Dtos;
using CompAuthApi.Core.Devices;
using CompAuthApi.Data.Context;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Endpoints;

public sealed class MobileAuthEndpoints : IEndpoints
{
    private const string DeviceCookieName = "authDeviceId";
    private const string EnablePurpose = "enable_2fa";
    private const string VerifyPurpose = "verify_2fa";
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    public void RegisterEndpoints(WebApplication app)
    {
        var mobile = app.MapGroup("/api/mobile-auth")
            .WithTags("Mobile Authentication")
            .RequireAuthorization(
                ServiceAuthenticationDefaults.RequireMobileBffServicePolicy);

        mobile.MapPost("/login", Login)
            .RequireRateLimiting("mobile-auth-sensitive");
        mobile.MapPost("/2fa/setup", SetupTwoFactor)
            .RequireRateLimiting("mobile-auth-sensitive");
        mobile.MapPost("/2fa/verify", VerifyTwoFactor)
            .RequireRateLimiting("mobile-auth-sensitive");
        mobile.MapPost("/2fa/verify-initial", VerifyInitialTwoFactor)
            .RequireRateLimiting("mobile-auth-sensitive");
        mobile.MapPost("/forgot-password", ForgotPassword)
            .RequireRateLimiting("mobile-auth-sensitive");
        mobile.MapPost("/reset-password", ResetPassword)
            .RequireRateLimiting("mobile-auth-sensitive");
        mobile.MapPost("/refresh-token", RefreshToken)
            .RequireRateLimiting("mobile-auth-standard");
        mobile.MapGet("/users/{authUserId:int}/identity", GetMobileUserIdentity)
            .RequireRateLimiting("mobile-auth-standard");

        mobile.MapPost("/logout", AuthEndpoints.Logout)
            .RequireAuthorization(
                ServiceAuthenticationDefaults.RequireCompanyUserAndMobileBffServicePolicy)
            .RequireRateLimiting("mobile-auth-standard");
        mobile.MapPost("/session/heartbeat", AuthEndpoints.Heartbeat)
            .RequireAuthorization(
                ServiceAuthenticationDefaults.RequireCompanyUserAndMobileBffServicePolicy)
            .RequireRateLimiting("mobile-auth-standard");
    }

    private static async Task<IResult> Login(
        CompAuthApiDbContext db,
        IConfiguration config,
        IGeoFenceService geoFenceService,
        IMobileAuthChallengeService challengeService,
        IDeviceSecurityService deviceSecurity,
        HttpContext httpContext,
        MobileLoginDto request)
    {
        if (!TryApplyDeviceId(httpContext, request.DeviceId, out var error))
        {
            return error!;
        }

        DeviceLoginAuthorization? deviceAuthorization = null;
        if (deviceSecurity.IsEnabled)
        {
            try
            {
                deviceAuthorization = await deviceSecurity.AuthorizeLoginAsync(
                    new MobileDeviceLoginProofRequest(
                        request.Login,
                        request.DeviceId,
                        request.DeviceChallengeId,
                        request.DeviceSignature),
                    httpContext.RequestAborted);
            }
            catch (Exception exception)
            {
                return MapDeviceException(exception);
            }
        }

        var result = await AuthEndpoints.Login(
            db,
            config,
            geoFenceService,
            httpContext,
            new LoginDto
            {
                Login = request.Login.Trim(),
                Password = request.Password
            });

        if (!TryReadResult(result, out var response))
        {
            return result;
        }

        string? purpose = null;
        if (ReadBoolean(response, "requiresTwoFactorEnable"))
        {
            purpose = EnablePurpose;
        }
        else if (ReadBoolean(response, "requiresTwoFactor"))
        {
            purpose = VerifyPurpose;
        }

        if (purpose is not null)
        {
            var challenge = challengeService.Issue(
                request.Login,
                request.DeviceId,
                purpose);
            response["challengeToken"] = challenge.Token;
            response["challengeExpiresIn"] = challenge.ExpiresIn;
        }

        if (deviceAuthorization is not null)
        {
            try
            {
                var completed = await deviceSecurity.CompleteLoginAsync(
                    deviceAuthorization,
                    request.Login,
                    JsonSerializer.SerializeToElement(response, WebJson),
                    httpContext.RequestAborted);
                return Results.Json(completed);
            }
            catch (Exception exception)
            {
                return MapDeviceException(exception);
            }
        }

        return purpose is null ? result : Results.Json(response);
    }

    private static async Task<IResult> SetupTwoFactor(
        CompAuthApiDbContext db,
        IQrCodeRepository qrCodeRepository,
        IMobileAuthChallengeService challengeService,
        IDeviceSecurityService deviceSecurity,
        MobileTwoFactorSetupDto request,
        CancellationToken cancellationToken)
    {
        if (!ValidateChallenge(challengeService, request, EnablePurpose))
        {
            return InvalidChallenge();
        }

        if (deviceSecurity.IsEnabled)
        {
            try
            {
                await deviceSecurity.AuthorizeTwoFactorAsync(
                    request.Login,
                    request.DeviceId,
                    request.ChallengeToken,
                    cancellationToken);
            }
            catch (Exception exception)
            {
                return MapDeviceException(exception);
            }
        }

        return await AuthEndpoints.EnableTwoFactorAuthentication(
            db,
            qrCodeRepository,
            new EnableTwoFactorDto { Login = request.Login.Trim() });
    }

    private static async Task<IResult> VerifyTwoFactor(
        CompAuthApiDbContext db,
        IConfiguration config,
        IGeoFenceService geoFenceService,
        IMobileAuthChallengeService challengeService,
        IDeviceSecurityService deviceSecurity,
        HttpContext httpContext,
        MobileVerifyTwoFactorDto request)
    {
        if (!ValidateChallenge(challengeService, request, VerifyPurpose))
        {
            return InvalidChallenge();
        }

        if (!TryApplyDeviceId(httpContext, request.DeviceId, out var error))
        {
            return error!;
        }

        DeviceLoginAuthorization? deviceAuthorization = null;
        if (deviceSecurity.IsEnabled)
        {
            try
            {
                deviceAuthorization = await deviceSecurity.AuthorizeTwoFactorAsync(
                    request.Login,
                    request.DeviceId,
                    request.ChallengeToken,
                    httpContext.RequestAborted);
            }
            catch (Exception exception)
            {
                return MapDeviceException(exception);
            }
        }

        var result = await AuthEndpoints.VerifyTwoFactorAuthentication(
            db,
            config,
            geoFenceService,
            httpContext,
            new VerifyTwoFactorDto
            {
                Login = request.Login.Trim(),
                Token = request.Token
            });
        return await CompleteTwoFactorResultAsync(
            result,
            deviceAuthorization,
            deviceSecurity,
            request,
            httpContext.RequestAborted);
    }

    private static async Task<IResult> VerifyInitialTwoFactor(
        CompAuthApiDbContext db,
        IConfiguration config,
        IGeoFenceService geoFenceService,
        IMobileAuthChallengeService challengeService,
        IDeviceSecurityService deviceSecurity,
        HttpContext httpContext,
        MobileVerifyTwoFactorDto request)
    {
        if (!ValidateChallenge(challengeService, request, EnablePurpose))
        {
            return InvalidChallenge();
        }

        if (!TryApplyDeviceId(httpContext, request.DeviceId, out var error))
        {
            return error!;
        }

        DeviceLoginAuthorization? deviceAuthorization = null;
        if (deviceSecurity.IsEnabled)
        {
            try
            {
                deviceAuthorization = await deviceSecurity.AuthorizeTwoFactorAsync(
                    request.Login,
                    request.DeviceId,
                    request.ChallengeToken,
                    httpContext.RequestAborted);
            }
            catch (Exception exception)
            {
                return MapDeviceException(exception);
            }
        }

        var result = await AuthEndpoints.VerifyInitialTwoFactorSetup(
            db,
            config,
            geoFenceService,
            httpContext,
            new VerifyTwoFactorDto
            {
                Login = request.Login.Trim(),
                Token = request.Token
            });
        return await CompleteTwoFactorResultAsync(
            result,
            deviceAuthorization,
            deviceSecurity,
            request,
            httpContext.RequestAborted);
    }

    private static Task<IResult> ForgotPassword(
        CompAuthApiDbContext db,
        [FromBody] ForgotPasswordDto request) =>
        AuthEndpoints.CustomerForgotPassword(db, request);

    private static Task<IResult> ResetPassword(
        CompAuthApiDbContext db,
        ResetPasswordDto request) =>
        AuthEndpoints.ResetPassword(db, request);

    private static Task<IResult> RefreshToken(
        CompAuthApiDbContext db,
        IConfiguration config,
        [FromBody] RefreshTokenRequestDto request) =>
        AuthEndpoints.RefreshToken(db, config, request);

    private static async Task<IResult> GetMobileUserIdentity(
        int authUserId,
        CompAuthApiDbContext db,
        CancellationToken cancellationToken)
    {
        var user = await db.Users
            .AsNoTracking()
            .Where(user => user.Id == authUserId)
            .Select(user => new
            {
                authUserId = user.Id,
                user.Username,
                user.Email,
                isActive = user.Active
            })
            .FirstOrDefaultAsync(cancellationToken);

        return user is null ? Results.NotFound() : Results.Ok(user);
    }

    private static bool ValidateChallenge(
        IMobileAuthChallengeService challengeService,
        MobileTwoFactorSetupDto request,
        string purpose) =>
        IsSafeDeviceId(request.DeviceId) &&
        !string.IsNullOrWhiteSpace(request.Login) &&
        challengeService.Validate(
            request.ChallengeToken,
            request.Login,
            request.DeviceId,
            purpose);

    private static bool TryApplyDeviceId(
        HttpContext context,
        string deviceId,
        out IResult? error)
    {
        if (!IsSafeDeviceId(deviceId))
        {
            error = Results.Problem(
                statusCode: StatusCodes.Status400BadRequest,
                title: "Invalid mobile device",
                detail: "Device ID must contain only letters, digits, hyphens, or underscores.",
                extensions: new Dictionary<string, object?>
                {
                    ["code"] = "invalid_device_id"
                });
            return false;
        }

        context.Request.Headers.Cookie =
            $"{DeviceCookieName}={Uri.EscapeDataString(deviceId)}";
        error = null;
        return true;
    }

    private static bool IsSafeDeviceId(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 64 &&
        value.All(character =>
            char.IsLetterOrDigit(character) || character is '-' or '_');

    private static bool TryReadResult(IResult result, out JsonObject response)
    {
        response = new JsonObject();
        if (result is not IValueHttpResult { Value: not null } valueResult)
        {
            return false;
        }

        var json = JsonSerializer.Serialize(valueResult.Value, WebJson);
        response = JsonNode.Parse(json) as JsonObject ?? new JsonObject();
        return response.Count > 0;
    }

    private static bool ReadBoolean(JsonObject response, string propertyName) =>
        response[propertyName]?.GetValue<bool>() == true;

    private static async Task<IResult> CompleteTwoFactorResultAsync(
        IResult result,
        DeviceLoginAuthorization? authorization,
        IDeviceSecurityService deviceSecurity,
        MobileVerifyTwoFactorDto request,
        CancellationToken cancellationToken)
    {
        if (authorization is null || !TryReadResult(result, out var response))
        {
            return result;
        }

        try
        {
            var completed = await deviceSecurity.CompleteTwoFactorAsync(
                authorization,
                request.Login,
                request.ChallengeToken,
                JsonSerializer.SerializeToElement(response, WebJson),
                cancellationToken);
            return Results.Json(completed);
        }
        catch (Exception exception)
        {
            return MapDeviceException(exception);
        }
    }

    private static IResult MapDeviceException(Exception exception) => exception switch
    {
        DeviceProofRequiredException => DeviceProblem(401, "device_proof_required", "An approved-device proof is required."),
        InvalidDeviceChallengeException => DeviceProblem(401, "invalid_device_challenge", "The device challenge is invalid or expired."),
        InvalidDeviceProofException => DeviceProblem(401, "invalid_device_proof", "Device ownership could not be verified."),
        InvalidDeviceLoginGrantException => DeviceProblem(401, "invalid_device_login_grant", "The device login grant is invalid or expired."),
        DeviceNotApprovedException => DeviceProblem(403, "device_not_approved", "This device is not approved for mobile access."),
        DeviceUserMismatchException => DeviceProblem(403, "device_user_mismatch", "This device is not approved for the authenticated user."),
        DeviceSecurityDisabledException => DeviceProblem(503, "device_security_disabled", "Approved-device security is disabled."),
        _ => throw exception
    };

    private static IResult DeviceProblem(int status, string code, string detail) =>
        Results.Problem(
            statusCode: status,
            detail: detail,
            extensions: new Dictionary<string, object?> { ["code"] = code });

    private static IResult InvalidChallenge() =>
        Results.Problem(
            statusCode: StatusCodes.Status401Unauthorized,
            title: "Invalid authentication challenge",
            detail: "The mobile authentication challenge is invalid or expired.",
            extensions: new Dictionary<string, object?>
            {
                ["code"] = "invalid_auth_challenge"
            });
}
