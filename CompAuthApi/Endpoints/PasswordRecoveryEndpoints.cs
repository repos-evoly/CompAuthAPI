using CompAuthApi.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Data.Context;

namespace CompAuthApi.Endpoints;

public sealed record VerifyPasswordRecoveryRequest(string? Login, string? Code);
public sealed record CompletePasswordRecoveryRequest(string? ResetToken, string? Password, string? ConfirmPassword);

public sealed class PasswordRecoveryEndpoints : IEndpoints
{
    public void RegisterEndpoints(WebApplication app)
    {
        var group = app.MapGroup("/api/auth/password-recovery");
        group.MapPost("/verify", Verify);
        group.MapPost("/complete", Complete);
    }

    public static async Task<IResult> Verify(VerifyPasswordRecoveryRequest request, CompAuthApiDbContext db,
        HttpContext context, ILogger<PasswordRecoveryEndpoints> logger)
    {
        context.Response.Headers.CacheControl = "no-store";
        var result = await new AuthenticatorRecoveryService(db).VerifyAsync(request.Login, request.Code,
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
        logger.LogInformation("Authenticator password recovery verification result {Outcome} for auth user {AuthUserId}", result.Success ? "verified" : result.Code, result.UserId);
        return result.Success ? Results.Ok(new { resetToken = result.Token, expiresIn = 300 }) : Failure(result);
    }

    public static async Task<IResult> Complete(CompletePasswordRecoveryRequest request, CompAuthApiDbContext db,
        HttpContext context, ILogger<PasswordRecoveryEndpoints> logger)
    {
        context.Response.Headers.CacheControl = "no-store";
        var result = await new AuthenticatorRecoveryService(db).CompleteAsync(request.ResetToken, request.Password, request.ConfirmPassword);
        logger.LogInformation("Authenticator password recovery completion result {Outcome} for auth user {AuthUserId}", result.Success ? "completed" : result.Code, result.UserId);
        return result.Success ? Results.Ok(new { success = true, message = "Password reset successful. Sign in again with a new authenticator code." }) : Failure(result);
    }

    private static IResult Failure(RecoveryResult result) => Results.Json(new
    {
        success = false, code = result.Code,
        message = result.Status == 429 ? "Too many recovery attempts. Try again in 15 minutes."
            : result.Code == "invalid_new_password" ? "Passwords must match, contain at least 8 characters, and use no more than 72 UTF-8 bytes."
            : "Unable to verify recovery. Check the username or email and use a new authenticator code. Contact support if you cannot access your authenticator."
    }, statusCode: result.Status);
}
