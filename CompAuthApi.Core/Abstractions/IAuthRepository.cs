using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using CompAuthApi.Core.Dtos;

namespace CompAuthApi.Core.Abstractions
{
    public interface IAuthRepository
    {
        // Registration
        Task<(bool Ok, string? Message, int? UserId)> Register(RegisterDto dto);

        // Login & Tokens
        Task<LoginResult> Login(LoginDto dto);
        Task<RefreshResult> RefreshToken(RefreshTokenRequestDto dto);

        // 2FA
        Task<Enable2FAResult> EnableTwoFactorAuthentication(EnableTwoFactorDto dto);
        Task<Verify2FAResult> VerifyInitialTwoFactorSetup(VerifyTwoFactorDto dto);
        Task<Verify2FAResult> VerifyTwoFactorAuthentication(VerifyTwoFactorDto dto);

        // Password reset flows
        Task<(bool Ok, string Message)> ForgotPassword(ForgotPasswordDto dto);
        Task<(bool Sent, string Message)> CustomerForgotPassword(ForgotPasswordDto dto);
        Task<(bool Ok, string Message)> ResetPassword(ResetPasswordDto dto);

        // Misc
        Task<(bool Ok, string Message)> Logout(HttpContext httpContext);
        Task<string?> GetRecaptchaSiteKey();
    }

    // Simple result models (same data your endpoints already return)
    public sealed record LoginResult(
        bool Success,
        bool RequiresTwoFactor,
        bool RequiresTwoFactorEnable,
        string? AccessToken,
        string? RefreshToken,
        string? KycToken,
        string? ErrorMessage
    );

    public sealed record RefreshResult(
        bool Success,
        string? AccessToken,
        string? RefreshToken
    );

    public sealed record Enable2FAResult(
        bool Success,
        string? SecretKey,
        string? QrCodePath,
        string? QrCodeImageBase64,
        string? ErrorMessage
    );

    public sealed record Verify2FAResult(
        bool Success,
        string? AccessToken,
        string? RefreshToken,
        string? ErrorMessage
    );
}
