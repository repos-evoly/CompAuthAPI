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

namespace CompAuthApi.Endpoints
{
    public class AuthEndpoints : IEndpoints
    {
        public void RegisterEndpoints(WebApplication app)
        {
            var auth = app.MapGroup("/api/auth");
            auth.MapPost("/register", Register);
            auth.MapPost("/login", Login);
            auth.MapPost("/enable-2fa", EnableTwoFactorAuthentication);
            auth.MapPost("/verify-2fa", VerifyTwoFactorAuthentication);
            auth.MapPost("/forgot-password", ForgotPassword);
            auth.MapPost("/reset-password", ResetPassword);
            auth.MapPost("/refresh-token", RefreshToken);
            auth.MapPost("/verify-initial-2fa", VerifyInitialTwoFactorSetup);
            auth.MapPost("/logout", Logout);
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
        public static async Task<IResult> Login(CompAuthApiDbContext db, IConfiguration config, HttpContext httpContext, LoginDto dto)
        {
            var jwtSection = config.GetSection("Jwt");

            if (string.IsNullOrEmpty(dto.Login) || string.IsNullOrEmpty(dto.Password))
                return TypedResults.NotFound("Invalid Credentials!");

            var user = await db.Users
          .Include(u => u.UserSecurity)
          .Include(u => u.Role)
          .FirstOrDefaultAsync(u =>
              u.Email == dto.Login ||
              u.Username == dto.Login);

            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.Password))
            return TypedResults.Json(new { Message = "Invalid username or password." }, statusCode: StatusCodes.Status401Unauthorized);
            var settings = await db.Settings.FirstOrDefaultAsync();
            bool isGlobal2FAEnabled = settings?.IsTwoFactorAuthEnabled ?? false;

            // 🔹 If 2FA is required globally and the user has it enabled, return "RequiresTwoFactor"
            if (isGlobal2FAEnabled)
            {
                if (user.UserSecurity == null || !user.UserSecurity.IsTwoFactorEnabled)
                {
                    return TypedResults.Ok(new { RequiresTwoFactorEnable = true });
                }

                return TypedResults.Ok(new { RequiresTwoFactor = true });
            }


            var accessToken = GenerateJwtTokenForCompAuthApi(user, config);
            var kycToken = GenerateJwtTokenForKycApi(user, config);
            var refreshToken = GenerateRefreshToken();


            user.UserSecurity ??= new UserSecurity { UserId = user.Id };
            user.UserSecurity.LastLogin = DateTimeOffset.Now;
            user.UserSecurity.RefreshToken = refreshToken;
            user.UserSecurity.LastLogin = DateTimeOffset.Now;
            user.UserSecurity.RefreshTokenExpiry = DateTime.Now.AddDays(30);

            await db.SaveChangesAsync();

            httpContext.Response.Cookies.Append("accessToken", accessToken,
            new CookieOptions
            {
                Expires = DateTime.Now.AddDays(7),
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            });
            httpContext.Response.Cookies.Append("refreshToken", refreshToken,
           new CookieOptions
           {
               Expires = DateTime.Now.AddDays(7),
               HttpOnly = true,
               Secure = true,
               SameSite = SameSiteMode.None
           });

            return TypedResults.Ok(new
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                KycToken = kycToken
            });
        }





        /// <summary> Enable Google Authenticator 2FA </summary>
        /// <summary> Enable Google Authenticator 2FA and save QR code </summary>
        public static async Task<IResult> EnableTwoFactorAuthentication(
             CompAuthApiDbContext db,
             IQrCodeRepository qrCodeRepository,
             EnableTwoFactorDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.Email == dto.Email);

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
            HttpContext httpContext,
            VerifyTwoFactorDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.Email == dto.Email);

            if (user == null || user.UserSecurity == null)
                return TypedResults.BadRequest("User not found or 2FA not enabled.");

            if (string.IsNullOrEmpty(user.UserSecurity.TwoFactorSecretKey))
                return TypedResults.BadRequest("2FA secret key is missing.");

            bool isValidOtp = VerifyOtp(dto.Token, user.UserSecurity.TwoFactorSecretKey);

            if (!isValidOtp)
                return TypedResults.BadRequest("Invalid OTP. Please scan and try again.");

            // ✅ Enable 2FA for the user
            user.UserSecurity.IsTwoFactorEnabled = true;

            // ✅ Generate Tokens
            var accessToken = GenerateJwtTokenForCompAuthApi(user, config);
            var refreshToken = GenerateRefreshToken();

            // ✅ Store Refresh Token
            user.UserSecurity.RefreshToken = refreshToken;
            user.UserSecurity.RefreshTokenExpiry = DateTime.Now.AddDays(30);

            await db.SaveChangesAsync();

            // ✅ Return Tokens
            return TypedResults.Ok(new
            {
                Message = "2FA setup successfully verified and enabled.",
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

        /// <summary> Verify Google Authenticator 2FA </summary>
        public static async Task<IResult> VerifyTwoFactorAuthentication(
            CompAuthApiDbContext db,
            IConfiguration config,
            HttpContext httpContext,
            VerifyTwoFactorDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity)
                                    .FirstOrDefaultAsync(u => u.Email == dto.Email);

            if (user == null || user.UserSecurity?.IsTwoFactorEnabled != true)
                return TypedResults.BadRequest("2FA is not enabled for this user.");

            if (string.IsNullOrEmpty(user.UserSecurity.TwoFactorSecretKey))
                return TypedResults.BadRequest("2FA secret key is missing.");

            bool isValidOtp = VerifyOtp(dto.Token, user.UserSecurity.TwoFactorSecretKey);

            if (!isValidOtp)
                return TypedResults.BadRequest("Invalid OTP. Please try again.");

            var accessToken = GenerateJwtTokenForCompAuthApi(user, config);


            var refreshToken = GenerateRefreshToken();

            user.UserSecurity.RefreshToken = refreshToken;
            user.UserSecurity.RefreshTokenExpiry = DateTime.Now.AddDays(30);

            await db.SaveChangesAsync();

            return TypedResults.Ok(new
            {
                Message = "2FA verification successful.",
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }


        /// <summary> Forgot Password (Request Password Reset) </summary>
        public static async Task<IResult> ForgotPassword(CompAuthApiDbContext db, ForgotPasswordDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity).FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null) return TypedResults.NotFound("User not found.");

            user.UserSecurity ??= new UserSecurity { UserId = user.Id };
            user.UserSecurity.PasswordResetToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            user.UserSecurity.PasswordResetTokenExpiry = DateTime.Now.AddMinutes(30);

            await db.SaveChangesAsync();

            return TypedResults.Ok("Password reset token sent.");
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

            // Update the LastLogout timestamp
            user.UserSecurity.LastLogout = DateTimeOffset.Now;
            await db.SaveChangesAsync();

            return TypedResults.Ok("Logged out successfully.");
        }



        private static string GenerateJwtTokenForCompAuthApi(User user, IConfiguration config)
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
        new Claim(ClaimTypes.Sid, user.Id.ToString())
    };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
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
                Expires = DateTime.Now.AddDays(7),
                Issuer = jwtSection["Issuer"],
                Audience = jwtSection["Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }


        public static async Task<IResult> RefreshToken(CompAuthApiDbContext db, IConfiguration config, HttpContext httpContext)
        {
            if (!httpContext.Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
                return TypedResults.BadRequest("Refresh token is missing");

            var user = await db.Users.Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.UserSecurity!.RefreshToken == refreshToken &&
                                        u.UserSecurity.RefreshTokenExpiry > DateTime.Now);

            if (user == null)
                return TypedResults.Unauthorized();

            var newAccessToken = GenerateJwtTokenForCompAuthApi(user, config);
            var newRefreshToken = GenerateRefreshToken();

            user.UserSecurity.RefreshToken = newRefreshToken;
            user.UserSecurity.RefreshTokenExpiry = DateTime.Now.AddDays(7);
            await db.SaveChangesAsync();

            httpContext.Response.Cookies.Append("authToken", newAccessToken, new CookieOptions
            {
                Expires = DateTime.Now.AddMinutes(30),
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            });

            httpContext.Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                Expires = DateTime.Now.AddDays(7),
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            });

            return TypedResults.Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken });
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
