using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Http;
using QRCoder;
using OtpNet;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using CompAuthApi.Core.Dtos;
using CompAuthApi.Abstractions;
using CompAuthApi.Core.Abstractions;
using System.Net;
using MailKit.Security;
using MimeKit;
using MimeKit.Utils;
using MailKit.Net.Smtp;
using Org.BouncyCastle.Asn1;

namespace CompAuthApi.Endpoints
{
    public class AuthEndpoints : IEndpoints
    {
        private const string SessionIdClaimType = "sessionId";
        private const string SessionCookieName = "authSessionId";
        private const string DeviceCookieName = "authDeviceId";
        private const int AbsoluteSessionMinutes = 180;
        private const int IdleSessionMinutes = 5;
        private const int HeartbeatIntervalMinutes = 5;
        private const int DefaultMaxLoginAttempts = 5;
        private const int DefaultLockTimeoutMinutes = 120;

        public void RegisterEndpoints(WebApplication app)
        {
            var auth = app.MapGroup("/api/auth");
            auth.MapPost("/register", Register);
            auth.MapPost("/login", Login);
            auth.MapPost("/enable-2fa", EnableTwoFactorAuthentication);
            auth.MapPost("/verify-2fa", VerifyTwoFactorAuthentication);
            auth.MapPost("/forgot-password", ForgotPassword);
            auth.MapPost("/customer-forgot-password", CustomerForgotPassword);
            auth.MapPost("/reset-password", ResetPassword);
            auth.MapPost("/refresh-token", RefreshToken);
            auth.MapPost("/verify-initial-2fa", VerifyInitialTwoFactorSetup);
            auth.MapPost("/logout", Logout);
            auth.MapPost("/session/heartbeat", Heartbeat);
        }

        /// <summary> User Registration </summary>
        public static async Task<IResult> Register(
            CompAuthApiDbContext db,
            RegisterDto dto)
        {
            // Check username OR email already taken:
            if (await db.Users.AnyAsync(u => u.Username == dto.Username))
                return TypedResults.BadRequest(new { Message = "Username already in use." });

            if (await db.Users.AnyAsync(u => u.Email == dto.Email))
                return TypedResults.BadRequest(new { Message = "Email already in use." });

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(dto.Password);
            var role = await db.Roles.FindAsync(dto.RoleId);
            if (role == null)
                return TypedResults.BadRequest(new { Message = "Invalid role." });

            var user = new User
            {
                Username = dto.Username,
                Email = dto.Email,
                Password = hashedPassword,
                RoleId = role.Id,
                Active = true,
                UserSecurity = new UserSecurity()
            };

            db.Users.Add(user);
            await db.SaveChangesAsync();

            return TypedResults.Ok(new { Message = "User registered.", UserId = user.Id });
        }


        /// <summary> Login with JWT </summary>
        /// Ask Mr ismat about Login and 2fa logic cases like if settings table has 2fa off but user has enabled 2fa will it ask him?? if settings has 2fa on it should force all users to enable 2fa? 
        public static async Task<IResult> Login(
            CompAuthApiDbContext db,
            IConfiguration config,
            IGeoFenceService geoFenceService,
            HttpContext httpContext,
            LoginDto dto)
        {
            var now = DateTimeOffset.UtcNow;
            var settings = await db.Settings.FirstOrDefaultAsync();
            var maxLoginAttempts = GetMaxLoginAttempts(settings);
            var lockTimeoutMinutes = GetLockTimeoutMinutes(settings);

            if (string.IsNullOrWhiteSpace(dto.Login) || string.IsNullOrWhiteSpace(dto.Password))
                return AuthError(
                    StatusCodes.Status401Unauthorized,
                    "AUTH_INVALID_CREDENTIALS",
                    "Invalid username or password.",
                    "اسم المستخدم أو كلمة المرور غير صحيحة.",
                    new { remainingAttempts = maxLoginAttempts });

            var user = await db.Users
                .Include(u => u.UserSecurity)
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u =>
                    u.Email == dto.Login ||
                    u.Username == dto.Login);

            if (user == null)
            {
                return AuthError(
                    StatusCodes.Status401Unauthorized,
                    "AUTH_INVALID_CREDENTIALS",
                    "Invalid username or password.",
                    "اسم المستخدم أو كلمة المرور غير صحيحة.",
                    new { remainingAttempts = (int?)null });
            }

            user.UserSecurity ??= new UserSecurity { UserId = user.Id };

            var lockedUntil = GetLockedUntil(user.UserSecurity, lockTimeoutMinutes);
            if (lockedUntil.HasValue && now < lockedUntil.Value)
            {
                return AccountLockedError(user.UserSecurity, lockedUntil.Value, maxLoginAttempts, now);
            }

            if (user.UserSecurity.IsLocked)
            {
                ClearLockout(user.UserSecurity);
            }

            if (!BCrypt.Net.BCrypt.Verify(dto.Password, user.Password))
            {
                user.UserSecurity.LoginAttemptCount++;

                if (user.UserSecurity.LoginAttemptCount >= maxLoginAttempts)
                {
                    user.UserSecurity.IsLocked = true;
                    user.UserSecurity.LastLock = now;
                    await db.SaveChangesAsync();

                    var newLockedUntil = now.AddMinutes(lockTimeoutMinutes);
                    return AccountLockedError(user.UserSecurity, newLockedUntil, maxLoginAttempts, now);
                }

                await db.SaveChangesAsync();
                return AuthError(
                    StatusCodes.Status401Unauthorized,
                    "AUTH_INVALID_CREDENTIALS",
                    "Invalid username or password.",
                    "اسم المستخدم أو كلمة المرور غير صحيحة.",
                    new
                    {
                        remainingAttempts = Math.Max(0, maxLoginAttempts - user.UserSecurity.LoginAttemptCount),
                        maxLoginAttempts
                    });
            }

            var requestedDeviceId = GetOrCreateDeviceId(httpContext);
            var sessionAvailabilityError = await ValidateSessionAvailability(db, user.Id, requestedDeviceId, now);
            if (sessionAvailabilityError != null)
                return TypedResults.Ok(sessionAvailabilityError);

            bool isGlobal2FAEnabled = settings?.IsTwoFactorAuthEnabled ?? false;

            if (isGlobal2FAEnabled)
            {
                ClearLockout(user.UserSecurity);
                await db.SaveChangesAsync();

                if (!user.UserSecurity.IsTwoFactorEnabled)
                    return TypedResults.Ok(new { RequiresTwoFactorEnable = true, DeviceId = requestedDeviceId });

                return TypedResults.Ok(new { RequiresTwoFactor = true, DeviceId = requestedDeviceId });
            }

            var geoFenceEvaluation = await EvaluateGeoFenceAsync(db, geoFenceService, user, httpContext, now);
            if (geoFenceEvaluation.Error != null)
                return TypedResults.Ok(geoFenceEvaluation.Error);

            var loginResponse = await CreateSessionAndTokenResponse(db, config, geoFenceService, geoFenceEvaluation, httpContext, user, requestedDeviceId, now);
            return TypedResults.Ok(loginResponse);
        }
      
      /// <summary> Enable Google Authenticator 2FA </summary>
        /// <summary> Enable Google Authenticator 2FA and save QR code </summary>
        public static async Task<IResult> EnableTwoFactorAuthentication(
             CompAuthApiDbContext db,
             IQrCodeRepository qrCodeRepository,
             EnableTwoFactorDto dto)
        {
            var user = await db.Users
     .Include(u => u.UserSecurity)
     .FirstOrDefaultAsync(u =>
         u.Email == dto.Login
      || u.Username == dto.Login);

            if (user == null) return TypedResults.NotFound("User not found.");

            using var generator = RandomNumberGenerator.Create();
            byte[] secretKeyBytes = KeyGeneration.GenerateRandomKey(20);
            string base32Secret = Base32Encoding.ToString(secretKeyBytes).TrimEnd('=');

            string qrCodeFileName = await qrCodeRepository.GenerateAndSaveQrCodeAsync(user.Email, base32Secret);

            if (user.UserSecurity == null)
            {
                user.UserSecurity = new UserSecurity
                {
                    UserId = user.Id,
                    TwoFactorSecretKey = base32Secret,
                    IsTwoFactorEnabled = false,  // 🚨 2FA is disabled until OTP is verified
                    PasswordResetToken = null,
                    PasswordResetTokenExpiry = null
                };
                db.UserSecurities.Add(user.UserSecurity);
            }
            else
            {
                user.UserSecurity.TwoFactorSecretKey = base32Secret;
                user.UserSecurity.IsTwoFactorEnabled = false; // 🚨 2FA is disabled until OTP is verified
            }

            await db.SaveChangesAsync();

            return TypedResults.Ok(new
            {
                SecretKey = base32Secret,
                QrCodePath = $"/attachments/{qrCodeFileName}"
            });
        }

        public static async Task<IResult> VerifyInitialTwoFactorSetup(
            CompAuthApiDbContext db,
            IConfiguration config,
            IGeoFenceService geoFenceService,
            HttpContext httpContext,
            VerifyTwoFactorDto dto)
        {
            var user = await db.Users
            .Include(u => u.UserSecurity)
            .Include(u => u.Role)
            .FirstOrDefaultAsync(u =>
                u.Email == dto.Login
            || u.Username == dto.Login);

            if (user == null || user.UserSecurity == null)
                return TypedResults.BadRequest("User not found or 2FA not enabled.");

            if (string.IsNullOrEmpty(user.UserSecurity.TwoFactorSecretKey))
                return TypedResults.BadRequest("2FA secret key is missing.");

            bool isValidOtp = VerifyOtp(dto.Token, user.UserSecurity.TwoFactorSecretKey);

            if (!isValidOtp)
                return TypedResults.BadRequest("Invalid OTP. Please scan and try again.");

            var now = DateTimeOffset.UtcNow;
            var requestedDeviceId = GetOrCreateDeviceId(httpContext);
            var sessionAvailabilityError = await ValidateSessionAvailability(db, user.Id, requestedDeviceId, now);
            if (sessionAvailabilityError != null)
                return TypedResults.Ok(sessionAvailabilityError);

            var geoFenceEvaluation = await EvaluateGeoFenceAsync(db, geoFenceService, user, httpContext, now);
            if (geoFenceEvaluation.Error != null)
                return TypedResults.Ok(geoFenceEvaluation.Error);

            // ✅ Enable 2FA for the user only after login policy checks pass.
            user.UserSecurity.IsTwoFactorEnabled = true;

            var response = await CreateSessionAndTokenResponse(db, config, geoFenceService, geoFenceEvaluation, httpContext, user, requestedDeviceId, now);

            return TypedResults.Ok(new
            {
                Message = "2FA setup successfully verified and enabled.",
                response.AccessToken,
                response.RefreshToken,
                response.KycToken,
                response.SessionId,
                response.DeviceId,
                response.SessionExpiresAt,
                response.HeartbeatIntervalMinutes,
                response.DebugClientIp
            });
        }

        /// <summary> Verify Google Authenticator 2FA </summary>
        public static async Task<IResult> VerifyTwoFactorAuthentication(
            CompAuthApiDbContext db,
            IConfiguration config,
            IGeoFenceService geoFenceService,
            HttpContext httpContext,
            VerifyTwoFactorDto dto)
        {
            var user = await db.Users
                .Include(u => u.UserSecurity)
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u =>
                    u.Email == dto.Login
                || u.Username == dto.Login);

            if (user == null || user.UserSecurity?.IsTwoFactorEnabled != true)
                return TypedResults.BadRequest("2FA is not enabled for this user.");

            if (string.IsNullOrEmpty(user.UserSecurity.TwoFactorSecretKey))
                return TypedResults.BadRequest("2FA secret key is missing.");

            bool isValidOtp = VerifyOtp(dto.Token, user.UserSecurity.TwoFactorSecretKey);

            if (!isValidOtp)
                return TypedResults.BadRequest("Invalid OTP. Please try again.");

            var now = DateTimeOffset.UtcNow;
            var requestedDeviceId = GetOrCreateDeviceId(httpContext);
            var sessionAvailabilityError = await ValidateSessionAvailability(db, user.Id, requestedDeviceId, now);
            if (sessionAvailabilityError != null)
                return TypedResults.Ok(sessionAvailabilityError);

            var geoFenceEvaluation = await EvaluateGeoFenceAsync(db, geoFenceService, user, httpContext, now);
            if (geoFenceEvaluation.Error != null)
                return TypedResults.Ok(geoFenceEvaluation.Error);

            var response = await CreateSessionAndTokenResponse(db, config, geoFenceService, geoFenceEvaluation, httpContext, user, requestedDeviceId, now);

            return TypedResults.Ok(new
            {
                Message = "2FA verification successful.",
                response.AccessToken,
                response.RefreshToken,
                response.KycToken,
                response.SessionId,
                response.DeviceId,
                response.SessionExpiresAt,
                response.HeartbeatIntervalMinutes,
                response.DebugClientIp
            });
        }


        /// <summary> Forgot Password (Request Password Reset) </summary>
        public static async Task<IResult> ForgotPassword(CompAuthApiDbContext db, ForgotPasswordDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity).FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null) return TypedResults.NotFound("User not found.");

            user.UserSecurity ??= new UserSecurity { UserId = user.Id };
            user.UserSecurity.PasswordResetToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            user.UserSecurity.PasswordResetTokenExpiry = DateTime.Now.AddMinutes(300);

            await db.SaveChangesAsync();

            return TypedResults.Ok("Password reset token sent.");
        }


        public static async Task<IResult> CustomerForgotPassword(
          CompAuthApiDbContext db,
          [FromBody] ForgotPasswordDto dto)
        {
            // 1) Look-up user
            var user = await db.Users
                               .Include(u => u.UserSecurity)
                               .FirstOrDefaultAsync(u => u.Email == dto.Email);

            if (user is null)
                return TypedResults.NotFound(new { message = "User not found." });

            // 2) Ensure UserSecurity row exists
            user.UserSecurity ??= new UserSecurity { UserId = user.Id };

            // 3) Generate reset token
            user.UserSecurity.PasswordResetToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            user.UserSecurity.PasswordResetTokenExpiry = DateTime.UtcNow.AddMinutes(300);
            await db.SaveChangesAsync();

            // 4) Build the e-mail body
            var resetBody = $"""
            Hi {user.Username},

            You (or someone pretending to be you) requested a password reset.
            Your reset code is: {user.UserSecurity.PasswordResetToken}

            This code will expire in 30 minutes.

            If you did not request this, please ignore this e-mail.

            — CompaniesGateway
            """;

            // 5) Create the MimeMessage
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("Companies Gateway", "OTP.info@bcd.ly"));
            message.To.Add(MailboxAddress.Parse(dto.Email));
            message.Subject = "Your password reset code";
            message.Date = DateTimeOffset.UtcNow;
            message.MessageId = MimeUtils.GenerateMessageId("bcd.ly");
            message.Body = new TextPart("plain") { Text = resetBody };

            // 6) Hard-coded SMTP settings (MailKit)
            const string smtpHost = "d303874.o.ess.barracudanetworks.com";
            const int smtpPort = 25;
            const bool useStartTls = true;
            const string smtpUser = "comp.info@bcd.ly";
            const string smtpPassword = "";  // <-- fill in if you have one

            bool sent = false;
            using var smtp = new SmtpClient { Timeout = 10_000 };

            try
            {
                // Connect (with or without STARTTLS)
                await smtp.ConnectAsync(
                    smtpHost,
                    smtpPort,
                    useStartTls
                      ? SecureSocketOptions.StartTls
                      : SecureSocketOptions.None
                );

                // Authenticate only if we have credentials
                if (!string.IsNullOrWhiteSpace(smtpPassword))
                    await smtp.AuthenticateAsync(smtpUser, smtpPassword);

                // Send the message
                await smtp.SendAsync(message);
                sent = true;
            }
            catch (Exception ex)
            {
                // Any failure before here means the message was not sent
                return TypedResults.Ok(new
                {
                    message = "Failed to send reset e-mail.",
                    detail = ex.Message
                });
            }
            finally
            {
                // Always attempt to disconnect, but swallow any errors here
                try
                {
                    await smtp.DisconnectAsync(true);
                }
                catch { }
            }

            // Return success if SendAsync succeeded
            return sent
                ? TypedResults.Ok(new { message = "Reset code sent to your e-mail." })
                : TypedResults.Ok(new { message = "Unknown error sending reset e-mail." });
        }
        /// <summary> Reset Password </summary>
        public static async Task<IResult> ResetPassword(CompAuthApiDbContext db, ResetPasswordDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.UserSecurity.PasswordResetToken == dto.PasswordToken &&
                                          u.UserSecurity.PasswordResetTokenExpiry > DateTime.Now);

            if (user == null) return TypedResults.BadRequest("Invalid or expired token.");

            // Hash the new password
            user.Password = BCrypt.Net.BCrypt.HashPassword(dto.Password);

            // Clear the reset token
            user.UserSecurity.PasswordResetToken = null;
            user.UserSecurity.PasswordResetTokenExpiry = null;

            await db.SaveChangesAsync();

            return TypedResults.Ok("Password reset successful.");
        }

        public static async Task<IResult> Logout(CompAuthApiDbContext db, HttpContext httpContext)
        {
            // Extract user ID from token claims
            var userIdClaim = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out int userId))
            {
                return TypedResults.BadRequest("Invalid user token.");
            }

            // Get the user including UserSecurity
            var user = await db.Users
                .Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
                return TypedResults.NotFound("User not found.");

            var sessionId = GetSessionId(httpContext);
            if (!string.IsNullOrWhiteSpace(sessionId))
            {
                var session = await db.UserSessions
                    .FirstOrDefaultAsync(s => s.SessionId == sessionId && s.UserId == userId && s.IsActive);

                if (session != null)
                {
                    session.IsActive = false;
                    session.LoggedOutAt = DateTimeOffset.UtcNow;
                }
            }

            // Update the LastLogout timestamp
            user.UserSecurity.LastLogout = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync();

            // Remove auth cookies set during login
            var cookieOptions = new CookieOptions
            {
                Path = "/",
                Secure = true,
                SameSite = SameSiteMode.None
            };
            httpContext.Response.Cookies.Delete("accessToken", cookieOptions);
            httpContext.Response.Cookies.Delete("refreshToken", cookieOptions);
            httpContext.Response.Cookies.Delete(SessionCookieName, cookieOptions);

            return TypedResults.Ok("Logged out successfully.");
        }

        public static async Task<IResult> Heartbeat(CompAuthApiDbContext db, HttpContext httpContext)
        {
            var sessionId = GetSessionId(httpContext);
            if (string.IsNullOrWhiteSpace(sessionId))
            {
                return AuthError(
                    StatusCodes.Status401Unauthorized,
                    "AUTH_SESSION_MISSING",
                    "Authentication session is missing.",
                    "جلسة المصادقة غير موجودة.",
                    null);
            }

            var now = DateTimeOffset.UtcNow;
            var session = await db.UserSessions.FirstOrDefaultAsync(s => s.SessionId == sessionId);
            if (session == null || !IsSessionActive(session, now))
            {
                if (session != null && session.IsActive)
                {
                    session.IsActive = false;
                    await db.SaveChangesAsync();
                }

                return AuthError(
                    StatusCodes.Status401Unauthorized,
                    "AUTH_SESSION_EXPIRED",
                    "Authentication session expired.",
                    "انتهت صلاحية جلسة المصادقة.",
                    null);
            }

            session.LastSeenAt = now;
            await db.SaveChangesAsync();

            return TypedResults.Ok(new
            {
                Success = true,
                SessionId = session.SessionId,
                LastSeenAt = session.LastSeenAt,
                SessionExpiresAt = session.ExpiresAt,
                HeartbeatIntervalMinutes
            });
        }

        private static async Task<SessionTokenResponse> CreateSessionAndTokenResponse(
            CompAuthApiDbContext db,
            IConfiguration config,
            IGeoFenceService geoFenceService,
            GeoFenceEvaluationDto geoFenceEvaluation,
            HttpContext httpContext,
            User user,
            string deviceId,
            DateTimeOffset now)
        {
            user.UserSecurity ??= new UserSecurity { UserId = user.Id };

            var refreshToken = GenerateRefreshToken();
            var session = new UserSession
            {
                UserId = user.Id,
                SessionId = Guid.NewGuid().ToString("N"),
                DeviceId = deviceId,
                RefreshToken = refreshToken,
                IpAddress = GetClientIp(httpContext),
                UserAgent = TrimToLength(httpContext.Request.Headers.UserAgent.ToString(), 512),
                LastSeenAt = now,
                ExpiresAt = now.AddMinutes(AbsoluteSessionMinutes),
                IsActive = true,
                CreatedAt = now,
                UpdatedAt = now
            };

            db.UserSessions.Add(session);
            await geoFenceService.RecordLoginEventAsync(user, geoFenceEvaluation, now, true, session.SessionId);

            ClearLockout(user.UserSecurity);
            user.UserSecurity.LastLogin = now;
            user.UserSecurity.RefreshToken = refreshToken;
            user.UserSecurity.RefreshTokenExpiry = now.AddDays(7);

            var accessToken = GenerateJwtTokenForCompAuthApi(user, config, session.SessionId);
            var kycToken = GenerateJwtTokenForKycApi(user, config);

            await db.SaveChangesAsync();

            return new SessionTokenResponse(
                accessToken,
                refreshToken,
                kycToken,
                session.SessionId,
                session.DeviceId,
                session.ExpiresAt,
                HeartbeatIntervalMinutes,
                geoFenceEvaluation.ShouldExposeDebugClientIp ? geoFenceEvaluation.DebugClientIp : null);
        }

        private static async Task<GeoFenceEvaluationDto> EvaluateGeoFenceAsync(
            CompAuthApiDbContext db,
            IGeoFenceService geoFenceService,
            User user,
            HttpContext httpContext,
            DateTimeOffset now)
        {
            var evaluation = await geoFenceService.EvaluateLoginAsync(user, httpContext, now);
            if (!evaluation.IsAllowed && evaluation.Error != null)
            {
                await geoFenceService.RecordLoginEventAsync(
                    user,
                    evaluation,
                    now,
                    false,
                    failureCode: evaluation.FailureCode,
                    failureReason: evaluation.FailureReason);
                await db.SaveChangesAsync();
            }

            return evaluation;
        }

        private static async Task<AuthApiErrorResponseDto?> ValidateSessionAvailability(
            CompAuthApiDbContext db,
            int userId,
            string deviceId,
            DateTimeOffset now)
        {
            await DeactivateExpiredSessions(db, now);

            var activeDeviceSession = await db.UserSessions
                .AsNoTracking()
                .FirstOrDefaultAsync(s =>
                    s.DeviceId == deviceId &&
                    s.IsActive &&
                    s.LoggedOutAt == null &&
                    s.ExpiresAt > now &&
                    s.LastSeenAt > now.AddMinutes(-IdleSessionMinutes));

            if (activeDeviceSession != null && activeDeviceSession.UserId != userId)
            {
                return BuildAuthError(
                    StatusCodes.Status409Conflict,
                    "AUTH_DEVICE_SESSION_ACTIVE",
                    "Another user is already signed in on this browser. Please logout first.",
                    "يوجد مستخدم آخر مسجل الدخول على هذا المتصفح. يرجى تسجيل الخروج أولا.",
                    new
                    {
                        activeUserId = activeDeviceSession.UserId,
                        activeSessionId = activeDeviceSession.SessionId,
                        lastSeenAt = activeDeviceSession.LastSeenAt,
                        sessionExpiresAt = activeDeviceSession.ExpiresAt
                    });
            }

            var activeUserSession = await db.UserSessions
                .AsNoTracking()
                .FirstOrDefaultAsync(s =>
                    s.UserId == userId &&
                    s.IsActive &&
                    s.LoggedOutAt == null &&
                    s.ExpiresAt > now &&
                    s.LastSeenAt > now.AddMinutes(-IdleSessionMinutes));

            if (activeUserSession != null)
            {
                return BuildAuthError(
                    StatusCodes.Status409Conflict,
                    "AUTH_USER_SESSION_ACTIVE",
                    "This user already has an active login session. Please logout from the active session or wait for it to expire.",
                    "هذا المستخدم لديه جلسة دخول نشطة بالفعل. يرجى تسجيل الخروج من الجلسة النشطة أو الانتظار حتى تنتهي.",
                    new
                    {
                        activeSessionId = activeUserSession.SessionId,
                        activeDeviceId = activeUserSession.DeviceId,
                        lastSeenAt = activeUserSession.LastSeenAt,
                        sessionExpiresAt = activeUserSession.ExpiresAt,
                        idleTimeoutMinutes = IdleSessionMinutes
                    });
            }

            return null;
        }

        private static async Task DeactivateExpiredSessions(CompAuthApiDbContext db, DateTimeOffset now)
        {
            var cutoff = now.AddMinutes(-IdleSessionMinutes);
            var expiredSessions = await db.UserSessions
                .Where(s =>
                    s.IsActive &&
                    s.LoggedOutAt == null &&
                    (s.ExpiresAt <= now || s.LastSeenAt <= cutoff))
                .ToListAsync();

            foreach (var session in expiredSessions)
            {
                session.IsActive = false;
            }

            if (expiredSessions.Count > 0)
                await db.SaveChangesAsync();
        }

        private static bool IsSessionActive(UserSession session, DateTimeOffset now)
        {
            return session.IsActive &&
                   session.LoggedOutAt == null &&
                   session.ExpiresAt > now &&
                   session.LastSeenAt > now.AddMinutes(-IdleSessionMinutes);
        }

        private static string GetOrCreateDeviceId(HttpContext httpContext)
        {
            var rawDeviceId = httpContext.Request.Cookies[DeviceCookieName];
            return IsSafeToken(rawDeviceId) ? rawDeviceId! : Guid.NewGuid().ToString("N");
        }

        private static string? GetSessionId(HttpContext httpContext)
        {
            var sessionClaim = httpContext.User.FindFirst(SessionIdClaimType)?.Value;
            if (IsSafeToken(sessionClaim)) return sessionClaim;

            var cookieSession = httpContext.Request.Cookies[SessionCookieName];
            return IsSafeToken(cookieSession) ? cookieSession : null;
        }

        private static bool IsSafeToken(string? value)
        {
            return !string.IsNullOrWhiteSpace(value) &&
                   value.Length <= 64 &&
                   value.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_');
        }

        private static string? GetClientIp(HttpContext httpContext)
        {
            var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            var ip = !string.IsNullOrWhiteSpace(forwardedFor)
                ? forwardedFor.Split(',').FirstOrDefault()?.Trim()
                : httpContext.Connection.RemoteIpAddress?.ToString();

            return TrimToLength(ip, 64);
        }

        private static string? TrimToLength(string? value, int maxLength)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            return value.Length <= maxLength ? value : value[..maxLength];
        }

        private static int GetMaxLoginAttempts(Settings? settings)
        {
            return settings?.MaxLoginAttempts > 0 ? settings.MaxLoginAttempts : DefaultMaxLoginAttempts;
        }

        private static int GetLockTimeoutMinutes(Settings? settings)
        {
            return settings?.LockTimeoutMinutes > 0 ? settings.LockTimeoutMinutes : DefaultLockTimeoutMinutes;
        }

        private static DateTimeOffset? GetLockedUntil(UserSecurity security, int lockTimeoutMinutes)
        {
            if (!security.IsLocked || security.LastLock == null) return null;
            return security.LastLock.Value.AddMinutes(lockTimeoutMinutes);
        }

        private static void ClearLockout(UserSecurity security)
        {
            security.IsLocked = false;
            security.LoginAttemptCount = 0;
            security.LastLock = null;
        }

        private static IResult AccountLockedError(
            UserSecurity security,
            DateTimeOffset lockedUntil,
            int maxLoginAttempts,
            DateTimeOffset now)
        {
            return AuthError(
                StatusCodes.Status423Locked,
                "AUTH_ACCOUNT_LOCKED",
                "Account is temporarily locked due to too many failed login attempts.",
                "تم قفل الحساب مؤقتا بسبب كثرة محاولات تسجيل الدخول الخاطئة.",
                new
                {
                    lockedUntil,
                    remainingMinutes = Math.Max(0, Math.Ceiling((lockedUntil - now).TotalMinutes)),
                    loginAttemptCount = security.LoginAttemptCount,
                    maxLoginAttempts
                });
        }

        private static IResult AuthError(
            int status,
            string code,
            string messageEn,
            string messageAr,
            object? details)
        {
            return TypedResults.Ok(BuildAuthError(status, code, messageEn, messageAr, details));
        }

        private static AuthApiErrorResponseDto BuildAuthError(
            int status,
            string code,
            string messageEn,
            string messageAr,
            object? details)
        {
            return new AuthApiErrorResponseDto
            {
                Success = false,
                Status = status,
                Code = code,
                Message = messageEn,
                MessageEn = messageEn,
                MessageAr = messageAr,
                Details = details
            };
        }

        private static string GenerateJwtTokenForCompAuthApi(User user, IConfiguration config, string sessionId)
        {
            var jwtSection = config.GetSection("Jwt");
            var keyString = jwtSection["Key"] ?? throw new InvalidOperationException("JWT Key is missing in configuration.");
            var key = Encoding.UTF8.GetBytes(keyString);
            var tokenHandler = new JwtSecurityTokenHandler();

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role?.TitleLT ?? "Unassigned"),
                new Claim(ClaimTypes.GroupSid, user.BranchId ?? ""),
                new Claim(ClaimTypes.Sid, user.Id.ToString()),
                new Claim(SessionIdClaimType, sessionId)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddMinutes(180),
                Issuer = jwtSection["Issuer"],
                Audience = jwtSection["Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private static string GenerateJwtTokenForKycApi(User user, IConfiguration config)
        {
            var jwtSection = config.GetSection("Jwt");
            var keyString = jwtSection["Key"] ?? throw new InvalidOperationException("JWT Key is missing in configuration.");
            var key = Encoding.UTF8.GetBytes(keyString);
            var tokenHandler = new JwtSecurityTokenHandler();

            // KYC-specific claims (matching the structure you need)
            var claims = new[]
                {
                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "ismat.ayash@gmail.com"),
                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "ismat.ayash@gmail.com"),
                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "arabic´"),  // FullNameAR
                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "Ismat Ayash Staging"),  // FullNameLT
                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/uri", ""),
                    new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "SuperAdmin"),
                    new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", "0011"),
                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid", "4"),
                    new Claim("nbf", "1742372867"),  // Example NBF timestamp (Unix time)
                    new Claim("exp", "1742977667"),  // Example EXP timestamp (Unix time)
                    new Claim("iss", "http://localhost:5000/"),
                    new Claim("aud", "http://localhost:5000/")
                };


            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddHours(1),
                Issuer = jwtSection["Issuer"],
                Audience = jwtSection["Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static async Task<IResult> RefreshToken(
            CompAuthApiDbContext db,
            IConfiguration config,
            [FromBody] RefreshTokenRequestDto dto)
        {
            if (dto is null || string.IsNullOrWhiteSpace(dto.RefreshToken))
                return TypedResults.BadRequest("Refresh token is missing.");

            var now = DateTimeOffset.UtcNow;
            var session = await db.UserSessions
                .Include(s => s.User)
                    .ThenInclude(u => u!.Role)
                .Include(s => s.User)
                    .ThenInclude(u => u!.UserSecurity)
                .FirstOrDefaultAsync(s =>
                    s.RefreshToken == dto.RefreshToken &&
                    s.IsActive &&
                    s.ExpiresAt > now);

            if (session?.User == null || session.User.UserSecurity == null || !IsSessionActive(session, now))
                return TypedResults.Unauthorized();

            var newAccessToken = GenerateJwtTokenForCompAuthApi(session.User, config, session.SessionId);
            var newRefreshToken = GenerateRefreshToken();

            session.RefreshToken = newRefreshToken;
            session.LastSeenAt = now;
            session.User.UserSecurity.RefreshToken = newRefreshToken;
            session.User.UserSecurity.RefreshTokenExpiry = now.AddDays(7);
            await db.SaveChangesAsync();

            // no cookies here; front-end stores them
            return TypedResults.Ok(new
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                SessionId = session.SessionId,
                DeviceId = session.DeviceId,
                SessionExpiresAt = session.ExpiresAt,
                HeartbeatIntervalMinutes
            });
        }
        private static bool VerifyOtp(string otp, string secretKey)
        {
            try
            {
                byte[] keyBytes = Base32Encoding.ToBytes(secretKey);

                var totp = new Totp(keyBytes, step: 30, totpSize: 6, mode: OtpHashMode.Sha1);

                bool isValid = totp.VerifyTotp(otp, out _, new VerificationWindow(previous: 1, future: 1));

                Console.WriteLine($"[DEBUG] OTP Received: {otp}");
                Console.WriteLine($"[DEBUG] Secret Key Used: {secretKey}");
                Console.WriteLine($"[DEBUG] OTP Valid: {isValid}");

                return isValid;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] OTP Verification Failed: {ex.Message}");
                return false;
            }
        }

        private static async Task<bool> VerifyRecaptcha(string secretKey, string recaptchaToken)
        {
            using var client = new HttpClient();
            var response = await client.PostAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={recaptchaToken}",
                null);

            var jsonResponse = await response.Content.ReadAsStringAsync();
            var result = System.Text.Json.JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);
            return result?.Success ?? false;
        }

        private sealed record SessionTokenResponse(
            string AccessToken,
            string RefreshToken,
            string KycToken,
            string SessionId,
            string DeviceId,
            DateTimeOffset SessionExpiresAt,
            int HeartbeatIntervalMinutes,
            GeoFenceDebugInfoDto? DebugClientIp);

        private class RecaptchaResponse
        {
            public bool Success { get; set; }
            public double Score { get; set; }
            public string? Action { get; set; }
            public string[]? ErrorCodes { get; set; }
        }

        public static async Task<IResult> GetRecaptchaSettings(CompAuthApiDbContext db)
        {
            var settings = await db.Settings.FirstOrDefaultAsync();
            return settings != null
                ? TypedResults.Ok(new { SiteKey = settings.RecaptchaSiteKey })
                : TypedResults.NotFound("No settings found.");
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

    }
}
