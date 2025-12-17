using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using CompAuthApi.Core.Abstractions;
using CompAuthApi.Core.Dtos;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using MimeKit.Utils;
using OtpNet;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;

namespace CompAuthApi.Data.Repositories
{
    public class AuthRepository : IAuthRepository
    {
        private readonly CompAuthApiDbContext _db;
        private readonly IConfiguration _config;
        private readonly IQrCodeRepository _qrRepo;

        public AuthRepository(CompAuthApiDbContext db, IConfiguration config, IQrCodeRepository qrRepo)
        {
            _db = db;
            _config = config;
            _qrRepo = qrRepo;
        }

        // ---------------- Register ----------------
        public async Task<(bool Ok, string? Message, int? UserId)> Register(RegisterDto dto)
        {
            if (await _db.Users.AnyAsync(u => u.Username == dto.Username))
                return (false, "Username already in use.", null);

            if (await _db.Users.AnyAsync(u => u.Email == dto.Email))
                return (false, "Email already in use.", null);

            var role = await _db.Roles.FindAsync(dto.RoleId);
            if (role == null)
                return (false, "Invalid role.", null);

            var user = new User
            {
                Username = dto.Username,
                Email = dto.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                RoleId = role.Id,
                Active = true,
                UserSecurity = new UserSecurity()
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();
            return (true, "User registered.", user.Id);
        }

        // ---------------- Login ----------------
        public async Task<LoginResult> Login(LoginDto dto)
        {
            // mirror your checks/behavior
            var user = await _db.Users
                .Include(u => u.UserSecurity)
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u => u.Email == dto.Login || u.Username == dto.Login);

            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.Password))
                return new LoginResult(false, false, false, null, null, null, "Invalid username or password.");

            var settings = await _db.Settings.FirstOrDefaultAsync();
            bool isGlobal2FAEnabled = settings?.IsTwoFactorAuthEnabled ?? false;

            if (isGlobal2FAEnabled)
            {
                if (user.UserSecurity == null || !user.UserSecurity.IsTwoFactorEnabled)
                    return new LoginResult(true, false, true, null, null, null, null); // RequiresTwoFactorEnable

                return new LoginResult(true, true, false, null, null, null, null);    // RequiresTwoFactor
            }

            var accessToken = GenerateJwtTokenForCompAuthApi(user);
            var kycToken = GenerateJwtTokenForKycApi(user);
            var refreshToken = GenerateRefreshToken();

            user.UserSecurity ??= new UserSecurity { UserId = user.Id };
            user.UserSecurity.LastLogin = DateTimeOffset.Now;
            user.UserSecurity.RefreshToken = refreshToken;
            user.UserSecurity.RefreshTokenExpiry = DateTime.Now.AddDays(30);
            await _db.SaveChangesAsync();

            return new LoginResult(true, false, false, accessToken, refreshToken, kycToken, null);
        }

        // ---------------- Refresh Token ----------------
        public async Task<RefreshResult> RefreshToken(RefreshTokenRequestDto dto)
        {
            var user = await _db.Users
                .Include(u => u.UserSecurity)
                .Include(u => u.Role) // important so role claim is set
                .FirstOrDefaultAsync(u =>
                    u.UserSecurity!.RefreshToken == dto.RefreshToken &&
                    u.UserSecurity.RefreshTokenExpiry > DateTime.UtcNow);

            if (user == null)
                return new RefreshResult(false, null, null);

            var newAccessToken = GenerateJwtTokenForCompAuthApi(user);
            var newRefreshToken = GenerateRefreshToken();

            user.UserSecurity!.RefreshToken = newRefreshToken;
            user.UserSecurity.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
            await _db.SaveChangesAsync();

            return new RefreshResult(true, newAccessToken, newRefreshToken);
        }

        // ---------------- Enable 2FA ----------------
        public async Task<Enable2FAResult> EnableTwoFactorAuthentication(EnableTwoFactorDto dto)
        {
            var user = await _db.Users
                .Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.Email == dto.Login || u.Username == dto.Login);

            if (user == null)
                return new Enable2FAResult(false, null, null, null, "User not found.");

            byte[] secretKeyBytes = KeyGeneration.GenerateRandomKey(20);
            string base32Secret = Base32Encoding.ToString(secretKeyBytes).TrimEnd('=');

            string qrFile = await _qrRepo.GenerateAndSaveQrCodeAsync(user.Email, base32Secret);
            var qrBytes = await _qrRepo.GetQrCodeAsync(qrFile);
            string? qrBase64 = (qrBytes != null && qrBytes.Length > 0)
                ? Convert.ToBase64String(qrBytes)
                : null;

            if (user.UserSecurity == null)
            {
                user.UserSecurity = new UserSecurity
                {
                    UserId = user.Id,
                    TwoFactorSecretKey = base32Secret,
                    IsTwoFactorEnabled = false,
                    PasswordResetToken = null,
                    PasswordResetTokenExpiry = null
                };
                _db.UserSecurities.Add(user.UserSecurity);
            }
            else
            {
                user.UserSecurity.TwoFactorSecretKey = base32Secret;
                user.UserSecurity.IsTwoFactorEnabled = false;
            }

            await _db.SaveChangesAsync();
            return new Enable2FAResult(true, base32Secret, $"/attachments/{qrFile}",
                qrBase64 != null ? $"data:image/png;base64,{qrBase64}" : null,
                null);
        }

        // ---------------- Verify Initial 2FA Setup ----------------
        public async Task<Verify2FAResult> VerifyInitialTwoFactorSetup(VerifyTwoFactorDto dto)
        {
            var user = await _db.Users
                .Include(u => u.UserSecurity)
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u => u.Email == dto.Login || u.Username == dto.Login);

            if (user == null || user.UserSecurity == null)
                return new Verify2FAResult(false, null, null, "User not found or 2FA not enabled.");

            if (string.IsNullOrEmpty(user.UserSecurity.TwoFactorSecretKey))
                return new Verify2FAResult(false, null, null, "2FA secret key is missing.");

            if (!VerifyOtp(dto.Token, user.UserSecurity.TwoFactorSecretKey))
                return new Verify2FAResult(false, null, null, "Invalid OTP. Please scan and try again.");

            user.UserSecurity.IsTwoFactorEnabled = true;

            var accessToken = GenerateJwtTokenForCompAuthApi(user);
            var refreshToken = GenerateRefreshToken();

            user.UserSecurity.RefreshToken = refreshToken;
            user.UserSecurity.RefreshTokenExpiry = DateTime.Now.AddDays(30);
            await _db.SaveChangesAsync();

            return new Verify2FAResult(true, accessToken, refreshToken, null);
        }

        // ---------------- Verify 2FA on Login ----------------
        public async Task<Verify2FAResult> VerifyTwoFactorAuthentication(VerifyTwoFactorDto dto)
        {
            var user = await _db.Users
                .Include(u => u.UserSecurity)
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u => u.Email == dto.Login || u.Username == dto.Login);

            if (user == null || user.UserSecurity?.IsTwoFactorEnabled != true)
                return new Verify2FAResult(false, null, null, "2FA is not enabled for this user.");

            if (string.IsNullOrEmpty(user.UserSecurity.TwoFactorSecretKey))
                return new Verify2FAResult(false, null, null, "2FA secret key is missing.");

            if (!VerifyOtp(dto.Token, user.UserSecurity.TwoFactorSecretKey))
                return new Verify2FAResult(false, null, null, "Invalid OTP. Please try again.");

            var accessToken = GenerateJwtTokenForCompAuthApi(user);
            var refreshToken = GenerateRefreshToken();

            user.UserSecurity.RefreshToken = refreshToken;
            user.UserSecurity.RefreshTokenExpiry = DateTime.Now.AddDays(30);
            await _db.SaveChangesAsync();

            return new Verify2FAResult(true, accessToken, refreshToken, null);
        }

        // ---------------- Forgot Password (code only) ----------------
        public async Task<(bool Ok, string Message)> ForgotPassword(ForgotPasswordDto dto)
        {
            var user = await _db.Users
                .Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.Email == dto.Email);

            if (user == null)
                return (false, "User not found.");

            user.UserSecurity ??= new UserSecurity { UserId = user.Id };
            user.UserSecurity.PasswordResetToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            user.UserSecurity.PasswordResetTokenExpiry = DateTime.Now.AddMinutes(300);
            await _db.SaveChangesAsync();

            return (true, "Password reset token sent.");
        }

        // ---------------- Forgot Password (customer e-mail send) ----------------
        public async Task<(bool Sent, string Message)> CustomerForgotPassword(ForgotPasswordDto dto)
        {
            var user = await _db.Users
                .Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.Email == dto.Email);

            if (user is null)
                return (false, "User not found.");

            user.UserSecurity ??= new UserSecurity { UserId = user.Id };
            user.UserSecurity.PasswordResetToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            user.UserSecurity.PasswordResetTokenExpiry = DateTime.UtcNow.AddMinutes(300);
            await _db.SaveChangesAsync();

            var resetBody = $"""
            Hi {user.Username},

            You (or someone pretending to be you) requested a password reset.
            Your reset code is: {user.UserSecurity.PasswordResetToken}

            This code will expire in 30 minutes.

            If you did not request this, please ignore this e-mail.

            — CompaniesGateway
            """;

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("Companies Gateway", "OTP.info@bcd.ly"));
            message.To.Add(MailboxAddress.Parse(dto.Email));
            message.Subject = "Your password reset code";
            message.Date = DateTimeOffset.UtcNow;
            message.MessageId = MimeUtils.GenerateMessageId("bcd.ly");
            message.Body = new TextPart("plain") { Text = resetBody };

            const string smtpHost = "d303874.o.ess.barracudanetworks.com";
            const int smtpPort = 25;
            const bool useStartTls = true;
            const string smtpUser = "comp.info@bcd.ly";
            const string smtpPassword = ""; // same behavior as before

            using var smtp = new SmtpClient { Timeout = 10_000 };
            try
            {
                await smtp.ConnectAsync(
                    smtpHost,
                    smtpPort,
                    useStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.None
                );

                if (!string.IsNullOrWhiteSpace(smtpPassword))
                    await smtp.AuthenticateAsync(smtpUser, smtpPassword);

                await smtp.SendAsync(message);
                await smtp.DisconnectAsync(true);
                return (true, "Reset code sent to your e-mail.");
            }
            catch (Exception ex)
            {
                try { await smtp.DisconnectAsync(true); } catch { }
                return (false, $"Failed to send reset e-mail. {ex.Message}");
            }
        }

        // ---------------- Reset Password ----------------
        public async Task<(bool Ok, string Message)> ResetPassword(ResetPasswordDto dto)
        {
            var user = await _db.Users
                .Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u =>
                    u.UserSecurity!.PasswordResetToken == dto.PasswordToken &&
                    u.UserSecurity.PasswordResetTokenExpiry > DateTime.Now);

            if (user == null)
                return (false, "Invalid or expired token.");

            user.Password = BCrypt.Net.BCrypt.HashPassword(dto.Password);
            user.UserSecurity!.PasswordResetToken = null;
            user.UserSecurity.PasswordResetTokenExpiry = null;
            await _db.SaveChangesAsync();

            return (true, "Password reset successful.");
        }

        // ---------------- Logout ----------------
        public async Task<(bool Ok, string Message)> Logout(HttpContext httpContext)
        {
            var userIdClaim = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out int userId))
                return (false, "Invalid user token.");

            var user = await _db.Users
                .Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
                return (false, "User not found.");

            user.UserSecurity!.LastLogout = DateTimeOffset.Now;
            await _db.SaveChangesAsync();
            return (true, "Logged out successfully.");
        }

        // ---------------- Recaptcha site key ----------------
        public async Task<string?> GetRecaptchaSiteKey()
        {
            var settings = await _db.Settings.FirstOrDefaultAsync();
            return settings?.RecaptchaSiteKey;
        }

        // ================= Helpers =================

        private string GenerateJwtTokenForCompAuthApi(User user)
        {
            var jwt = _config.GetSection("Jwt");
            var keyString = jwt["Key"] ?? throw new InvalidOperationException("JWT Key is missing in configuration.");
            var key = Encoding.UTF8.GetBytes(keyString);
            var tokenHandler = new JwtSecurityTokenHandler();

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role?.TitleLT ?? "Unassigned"),
                new Claim(ClaimTypes.GroupSid, user.BranchId ?? ""),
                new Claim(ClaimTypes.Sid, user.Id.ToString())
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddMinutes(200),
                Issuer = jwt["Issuer"],
                Audience = jwt["Audience"],
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GenerateJwtTokenForKycApi(User user)
        {
            var jwt = _config.GetSection("Jwt");
            var keyString = jwt["Key"] ?? throw new InvalidOperationException("JWT Key is missing in configuration.");
            var key = Encoding.UTF8.GetBytes(keyString);
            var tokenHandler = new JwtSecurityTokenHandler();

            // (kept identical to your code)
            var claims = new[]
            {
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "ismat.ayash@gmail.com"),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "ismat.ayash@gmail.com"),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "arabic´"),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "Ismat Ayash Staging"),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/uri", ""),
                new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "SuperAdmin"),
                new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", "0011"),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid", "4"),
                new Claim("nbf", "1742372867"),
                new Claim("exp", "1742977667"),
                new Claim("iss", "http://localhost:5000/"),
                new Claim("aud", "http://localhost:5000/")
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddHours(1),
                Issuer = jwt["Issuer"],
                Audience = jwt["Audience"],
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private static bool VerifyOtp(string otp, string secretKey)
        {
            try
            {
                byte[] keyBytes = Base32Encoding.ToBytes(secretKey);
                var totp = new Totp(keyBytes, step: 30, totpSize: 6, mode: OtpHashMode.Sha1);
                return totp.VerifyTotp(otp, out _, new VerificationWindow(previous: 1, future: 1));
            }
            catch { return false; }
        }

        private static string GenerateRefreshToken()
        {
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
    }
}
