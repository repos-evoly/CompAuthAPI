using System.Security.Cryptography;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using OtpNet;

namespace CompAuthApi.Core.Authentication;

public sealed record ReenrollmentResult(
    string Status, Guid? RequestId = null, bool AlreadyRequested = false, bool CanContinue = false,
    SetupSecret? Setup = null, int HttpStatus = 200, string? Code = null);

public sealed partial class AuthenticatorRecoveryService
{
    private const string ReenrollmentPurpose = "2fa-reenroll";

    public Task<ReenrollmentResult> ReadReenrollmentAsync(int userId, string login, string deviceId, string? key) =>
        Transaction(async db =>
        {
            var user = await LockReenrollmentUserAsync(db, userId);
            if (!MatchesLogin(user, login)) return InvalidReenrollment();
            var request = await FindOpenRequestAsync(db, userId);
            return request is null ? new("none") : View(request, OwnsRequest(request, user!, deviceId, key));
        });

    public Task<ReenrollmentResult> RequestReenrollmentAsync(
        int userId, string login, string deviceId, string challenge, string key) =>
        RequestReenrollmentAsync(userId, login, deviceId, key, string.Equals(key, challenge, StringComparison.Ordinal));

    public Task<ReenrollmentResult> RequestReenrollmentAsync(
        int userId, string login, string deviceId, string key, bool keyAuthorizedForNewRequest) =>
        Transaction(async db =>
        {
            var user = await LockReenrollmentUserAsync(db, userId);
            if (!MatchesLogin(user, login)) return InvalidReenrollment();
            var existing = await FindOpenRequestAsync(db, userId);
            if (existing is not null)
                return View(existing, OwnsRequest(existing, user!, deviceId, key)) with { AlreadyRequested = true };

            if (!keyAuthorizedForNewRequest)
                return new("none", HttpStatus: 409, Code: "recovery_key_needs_current_challenge");

            var request = new AuthenticatorReenrollment
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                DeviceId = deviceId,
                RequestKeyHash = Hash(key),
                PasswordFingerprint = Hash(user!.Password),
                PreviousSecretFingerprint = Hash(user.UserSecurity.TwoFactorSecretKey!),
                RequestedAt = clock.GetUtcNow()
            };
            db.AuthenticatorReenrollments.Add(request);
            return View(request, true);
        });

    public Task<ReenrollmentResult> SetReenrollmentDecisionAsync(
        int userId, Guid requestId, int staffId, bool approve) =>
        Transaction(async db =>
        {
            var user = await LockReenrollmentUserAsync(db, userId);
            var request = await db.AuthenticatorReenrollments
                .SingleOrDefaultAsync(r => r.Id == requestId && r.UserId == userId);
            if (request is null) return new("none", HttpStatus: 404, Code: "recovery_request_not_found");
            if (request.ClosedAt is not null) return View(request, false);
            if (approve)
            {
                if (!IsEligible(user) || !MatchesCredentials(request, user!))
                    return new("requested", request.Id, HttpStatus: 409, Code: "recovery_credentials_changed");
                if (request.Status == AuthenticatorReenrollmentStatus.Requested)
                {
                    request.Status = AuthenticatorReenrollmentStatus.Approved;
                    request.ApprovedByAuthUserId = staffId;
                    request.ApprovedAt = clock.GetUtcNow();
                }
            }
            else
            {
                request.Status = AuthenticatorReenrollmentStatus.Cancelled;
                request.CancelledByAuthUserId = staffId;
                request.CancelledAt = clock.GetUtcNow();
                request.ClosedAt = request.CancelledAt;
                request.ProtectedSetupSecret = null;
            }
            return View(request, false) with { RequestId = request.Id };
        });

    public Task<ReenrollmentResult> PrepareReenrollmentAsync(
        int userId, string login, string deviceId, string key, IDataProtector protector) =>
        UseApprovedReenrollmentAsync(userId, login, deviceId, key, (_, user, request) =>
        {
            var secret = GetPendingSecret(request, protector);
            if (secret is null)
            {
                secret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20)).TrimEnd('=');
                request.ProtectedSetupSecret = protector.Protect(secret);
            }
            return Task.FromResult(View(request, true) with { Setup = new(user.Email, secret) });
        });

    public Task<ReenrollmentResult> CompleteReenrollmentAsync(
        int userId, string login, string deviceId, string key, string? code, IDataProtector protector) =>
        UseApprovedReenrollmentAsync(userId, login, deviceId, key, async (db, user, request) =>
        {
            if (!await Allow(db, "reenrollment-user:" + user.Id, 5))
                return new("approved", request.Id, HttpStatus: 429, Code: "recovery_rate_limited");
            var secret = GetPendingSecret(request, protector);
            if (!Match(code, secret, out var step))
                return new("approved", request.Id, HttpStatus: 400, Code: "invalid_recovery_otp");

            // Mark this time step so the code used to confirm setup cannot also sign in.
            if (!await db.AuthenticatorUsedSteps.AnyAsync(row => row.UserId == user.Id && row.TimeStep == step))
                db.AuthenticatorUsedSteps.Add(new AuthenticatorUsedStep
                {
                    UserId = user.Id, TimeStep = step, Purpose = ReenrollmentPurpose, UsedUtc = Now
                });
            user.UserSecurity.TwoFactorSecretKey = secret;
            user.UserSecurity.QrCodePath = null;
            user.UserSecurity.RefreshToken = null;
            user.UserSecurity.RefreshTokenExpiry = null;
            request.Status = AuthenticatorReenrollmentStatus.Completed;
            request.ClosedAt = clock.GetUtcNow();
            request.ProtectedSetupSecret = null;
            await RevokeUserSessionsAsync(db, user.Id);
            return View(request, false);
        }, allowCompletedReceipt: true);

    private Task<ReenrollmentResult> UseApprovedReenrollmentAsync(
        int userId, string login, string deviceId, string key,
        Func<CompAuthApiDbContext, User, AuthenticatorReenrollment, Task<ReenrollmentResult>> action,
        bool allowCompletedReceipt = false) =>
        Transaction(async db =>
        {
            var user = await LockReenrollmentUserAsync(db, userId);
            if (!MatchesLogin(user, login)) return InvalidReenrollment();
            var request = await FindOpenRequestAsync(db, userId);
            if (request is null && allowCompletedReceipt && !string.IsNullOrEmpty(key))
            {
                var keyHash = Hash(key);
                var passwordHash = Hash(user!.Password);
                var receipt = await db.AuthenticatorReenrollments.FirstOrDefaultAsync(item =>
                    item.UserId == userId && item.DeviceId == deviceId && item.RequestKeyHash == keyHash &&
                    item.PasswordFingerprint == passwordHash && item.Status == AuthenticatorReenrollmentStatus.Completed);
                if (receipt is not null) return View(receipt, false);
            }
            if (request?.Status != AuthenticatorReenrollmentStatus.Approved ||
                !OwnsRequest(request, user!, deviceId, key))
                return InvalidReenrollment();
            return await action(db, user!, request);
        });

    private static Task<User?> LockReenrollmentUserAsync(CompAuthApiDbContext db, int userId) =>
        (db.Database.IsSqlServer()
            ? db.Users.FromSqlInterpolated($"SELECT * FROM [Users] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {userId}")
            : db.Users.Where(user => user.Id == userId))
        .Include(user => user.UserSecurity).SingleOrDefaultAsync();

    private static Task<AuthenticatorReenrollment?> FindOpenRequestAsync(CompAuthApiDbContext db, int userId) =>
        db.AuthenticatorReenrollments.SingleOrDefaultAsync(request => request.UserId == userId && request.ClosedAt == null);

    private static bool IsEligible(User? user) =>
        user is { Active: true, UserSecurity.IsTwoFactorEnabled: true, UserSecurity.IsLocked: false } &&
        !string.IsNullOrWhiteSpace(user.UserSecurity.TwoFactorSecretKey);

    private static bool MatchesLogin(User? user, string login) =>
        IsEligible(user) && (string.Equals(user!.Username, login.Trim(), StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(user.Email, login.Trim(), StringComparison.OrdinalIgnoreCase));

    private static bool MatchesCredentials(AuthenticatorReenrollment request, User user) =>
        request.PasswordFingerprint == Hash(user.Password) &&
        request.PreviousSecretFingerprint == Hash(user.UserSecurity.TwoFactorSecretKey ?? "");

    private static bool OwnsRequest(AuthenticatorReenrollment request, User user, string deviceId, string? key) =>
        key is { Length: > 0 and <= 4096 } && request.DeviceId == deviceId &&
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(request.RequestKeyHash), Convert.FromHexString(Hash(key))) &&
        MatchesCredentials(request, user);

    // If a server key was replaced while a QR was on screen, the same approved request can create a fresh QR.
    private static string? GetPendingSecret(AuthenticatorReenrollment request, IDataProtector protector)
    {
        if (request.ProtectedSetupSecret is null) return null;
        try { return protector.Unprotect(request.ProtectedSetupSecret); }
        catch (CryptographicException) { return null; }
    }

    private static ReenrollmentResult View(AuthenticatorReenrollment request, bool owner) =>
        new(request.Status.ToString().ToLowerInvariant(), owner || request.ClosedAt is not null ? request.Id : null,
            CanContinue: owner && request.Status == AuthenticatorReenrollmentStatus.Approved);

    private static ReenrollmentResult InvalidReenrollment() =>
        new("none", HttpStatus: 403, Code: "recovery_not_authorized");
}
