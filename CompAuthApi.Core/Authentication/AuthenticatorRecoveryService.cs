using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using OtpNet;

namespace CompAuthApi.Core.Authentication;

public sealed record RecoveryResult(bool Success, string? Token = null, int Status = 400, string Code = "invalid_recovery", int? UserId = null);
public sealed record SetupSecret(string Email, string Secret);

// Short-lived grants are stored hashed. All decisions and consumption run in a
// serializable transaction; retries always use a fresh context/change tracker.
public sealed class AuthenticatorRecoveryService
{
    public const string ResetPurpose = "password-reset";
    public const string SetupPurpose = "authenticator-setup";
    private readonly DbContextOptions<CompAuthApiDbContext> options;
    private readonly TimeProvider clock;
    public AuthenticatorRecoveryService(CompAuthApiDbContext db, TimeProvider? clock = null)
    {
        options = new DbContextOptionsBuilder<CompAuthApiDbContext>(
            (DbContextOptions<CompAuthApiDbContext>)db.GetService<IDbContextOptions>()).UseModel(db.Model).Options;
        this.clock = clock ?? TimeProvider.System;
    }
    private DateTime Now => clock.GetUtcNow().UtcDateTime;
    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private static bool TokenFormat(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);

    private async Task<T> Transaction<T>(Func<CompAuthApiDbContext, Task<T>> action)
    {
        await using var strategyDb = new CompAuthApiDbContext(options);
        return await strategyDb.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            await using var db = new CompAuthApiDbContext(options);
            await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            var result = await action(db);
            await db.SaveChangesAsync();
            await tx.CommitAsync();
            return result;
        });
    }

    // Resolve aliases before throttling, so username and email share the same limit.
    private static async Task<User?> FindUser(CompAuthApiDbContext db, string? login)
    {
        var normalized = (login ?? "").Trim().ToUpperInvariant();
        if (normalized.Length is 0 or > 150) return null;
        var matches = await db.Users.Include(u => u.UserSecurity)
            .Where(u => u.Username.ToUpper() == normalized || u.Email.ToUpper() == normalized).Take(2).ToListAsync();
        return matches.Count == 1 ? matches[0] : null;
    }

    private async Task<bool> Allow(CompAuthApiDbContext db, string key, int limit)
    {
        var hash = Hash(key);
        // Lock missing key ranges too: concurrent inserts/updates cannot bypass a limit.
        var row = db.Database.IsSqlServer()
            ? await db.PasswordRecoveryThrottles.FromSqlInterpolated($"SELECT * FROM [PasswordRecoveryThrottles] WITH (UPDLOCK, HOLDLOCK) WHERE [KeyHash] = {hash}").SingleOrDefaultAsync()
            : await db.PasswordRecoveryThrottles.SingleOrDefaultAsync(r => r.KeyHash == hash);
        if (row == null)
        {
            row = new PasswordRecoveryThrottle { KeyHash = hash, WindowStartedUtc = Now };
            db.PasswordRecoveryThrottles.Add(row);
        }
        if (row.WindowStartedUtc.AddMinutes(15) <= Now)
        {
            row.AttemptCount = 0;
            row.WindowStartedUtc = Now;
        }
        if (row.AttemptCount >= limit) return false;
        row.AttemptCount++;
        return true;
    }

    private AuthenticatorActionGrant Grant(User user, string raw, string purpose) => new()
    {
        TokenHash = Hash(raw), UserId = user.Id, Purpose = purpose,
        PasswordFingerprint = Hash(user.Password),
        SecretFingerprint = purpose == ResetPurpose ? Hash(user.UserSecurity.TwoFactorSecretKey!) : null,
        CreatedUtc = Now, ExpiresUtc = Now.AddMinutes(5)
    };

    private async Task<AuthenticatorActionGrant?> GetGrant(CompAuthApiDbContext db, string? raw, string purpose)
    {
        if (!TokenFormat(raw)) return null;
        var hash = Hash(raw!);
        var grant = db.Database.IsSqlServer()
            ? await db.AuthenticatorActionGrants.FromSqlInterpolated($"SELECT * FROM [AuthenticatorActionGrants] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {hash}").SingleOrDefaultAsync()
            : await db.AuthenticatorActionGrants.SingleOrDefaultAsync(g => g.TokenHash == hash);
        return grant != null && grant.Purpose == purpose && grant.ConsumedUtc == null && grant.ExpiresUtc > Now ? grant : null;
    }

    private bool Match(string? code, string? secret, out long step)
    {
        step = 0;
        if (code == null || !Regex.IsMatch(code, @"\A[0-9]{6}\z") || string.IsNullOrWhiteSpace(secret)) return false;
        try
        {
            return new Totp(Base32Encoding.ToBytes(secret)).VerifyTotp(Now, code, out step, new VerificationWindow(1, 1));
        }
        catch (ArgumentException) { return false; }
        catch (FormatException) { return false; }
    }

    private async Task<bool> Consume(CompAuthApiDbContext db, User user, string? code, string purpose)
    {
        if (!Match(code, user.UserSecurity?.TwoFactorSecretKey, out var step)) return false;
        if (await db.AuthenticatorUsedSteps.AnyAsync(r => r.UserId == user.Id && r.TimeStep == step)) return false;
        db.AuthenticatorUsedSteps.Add(new AuthenticatorUsedStep { UserId = user.Id, TimeStep = step, Purpose = purpose, UsedUtc = Now });
        return true;
    }

    public Task<RecoveryResult> VerifyAsync(string? login, string? code, string ip) => Transaction(async db =>
    {
        var user = await FindUser(db, login);
        var allowedIp = await Allow(db, "recovery-ip:" + ip, 30);
        if (!allowedIp) return new RecoveryResult(false, Status: 429, Code: "recovery_rate_limited");
        var allowedAccount = await Allow(db, user == null ? "recovery-login:" + (login ?? "").Trim().ToUpperInvariant() : "recovery-user:" + user.Id, 5);
        if (!allowedIp || !allowedAccount) return new RecoveryResult(false, Status: 429, Code: "recovery_rate_limited");
        if (user?.Active != true || user.UserSecurity?.IsTwoFactorEnabled != true ||
            (user.UserSecurity.IsLocked && user.UserSecurity.LastLock == null) ||
            !await Consume(db, user, code, ResetPurpose)) return new RecoveryResult(false);
        var oldGrants = await db.AuthenticatorActionGrants.Where(g => g.UserId == user.Id && g.Purpose == ResetPurpose && g.ConsumedUtc == null).ToListAsync();
        foreach (var grant in oldGrants) grant.ConsumedUtc = Now;
        var token = NewToken();
        db.AuthenticatorActionGrants.Add(Grant(user, token, ResetPurpose));
        return new RecoveryResult(true, token, 200, UserId: user.Id);
    });

    public Task<RecoveryResult> CompleteAsync(string? token, string? password, string? confirm) => Transaction(async db =>
    {
        if (password == null || password.Length < 8 || Encoding.UTF8.GetByteCount(password) > 72 || password != confirm)
            return new RecoveryResult(false, Code: "invalid_new_password");
        var grant = await GetGrant(db, token, ResetPurpose);
        if (grant == null) return new RecoveryResult(false);
        var user = await db.Users.Include(u => u.UserSecurity).SingleOrDefaultAsync(u => u.Id == grant.UserId);
        if (user?.Active != true || user.UserSecurity?.IsTwoFactorEnabled != true ||
            (user.UserSecurity.IsLocked && user.UserSecurity.LastLock == null) ||
            grant.PasswordFingerprint != Hash(user.Password) || grant.SecretFingerprint != Hash(user.UserSecurity.TwoFactorSecretKey ?? ""))
            return new RecoveryResult(false);
        user.Password = BCrypt.Net.BCrypt.HashPassword(password);
        user.PasswordToken = null;
        user.UserSecurity.PasswordResetToken = null;
        user.UserSecurity.PasswordResetTokenExpiry = null;
        user.UserSecurity.RefreshToken = null;
        user.UserSecurity.RefreshTokenExpiry = null;
        // Only clear a timed password-attempt lock. Disabled accounts are never enabled.
        if (user.UserSecurity.LastLock != null)
        {
            user.UserSecurity.IsLocked = false;
            user.UserSecurity.LastLock = null;
            user.UserSecurity.LoginAttemptCount = 0;
        }
        var sessions = await db.UserSessions.Where(s => s.UserId == user.Id && s.IsActive).ToListAsync();
        foreach (var session in sessions) { session.IsActive = false; session.RefreshToken = null; session.LoggedOutAt = clock.GetUtcNow(); }
        var devices = await db.DeviceSessions.Where(s => s.AuthUserId == user.Id && s.RevokedAt == null).ToListAsync();
        foreach (var session in devices) session.RevokedAt = clock.GetUtcNow();
        var grants = await db.AuthenticatorActionGrants.Where(g => g.UserId == user.Id && g.ConsumedUtc == null).ToListAsync();
        foreach (var item in grants) item.ConsumedUtc = Now;
        return new RecoveryResult(true, Status: 200, UserId: user.Id);
    });

    public Task<string?> IssueSetupAsync(int userId) => Transaction(async db =>
    {
        var user = await db.Users.Include(u => u.UserSecurity).SingleOrDefaultAsync(u => u.Id == userId);
        if (user?.Active != true || user.UserSecurity?.IsTwoFactorEnabled == true) return null;
        var token = NewToken();
        db.AuthenticatorActionGrants.Add(Grant(user, token, SetupPurpose));
        return token;
    });

    public Task<SetupSecret?> PrepareSetupAsync(string login, string? token, bool verifiedMobile = false) => Transaction(async db =>
    {
        var user = await FindUser(db, login);
        if (user?.Active != true || user.UserSecurity?.IsTwoFactorEnabled == true) return null;
        if (!verifiedMobile)
        {
            var grant = await GetGrant(db, token, SetupPurpose);
            if (grant?.UserId != user.Id || grant.PasswordFingerprint != Hash(user.Password)) return null;
        }
        user.UserSecurity ??= new UserSecurity { UserId = user.Id };
        // Refreshing the setup screen reuses a pending secret; it never rotates an enrolled secret.
        user.UserSecurity.TwoFactorSecretKey ??= Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20)).TrimEnd('=');
        return new SetupSecret(user.Email, user.UserSecurity.TwoFactorSecretKey);
    });

    public Task<bool> ConsumeLoginCodeAsync(int userId, string code, bool initial) => Transaction(async db =>
    {
        var user = await db.Users.Include(u => u.UserSecurity).SingleOrDefaultAsync(u => u.Id == userId);
        if (user?.Active != true || user.UserSecurity == null || user.UserSecurity.IsTwoFactorEnabled == initial) return false;
        return await Consume(db, user, code, initial ? SetupPurpose : "login");
    });
}
