using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Dtos;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using CompAuthApi.Data.Migrations;
using CompAuthApi.Endpoints;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Microsoft.Extensions.Logging.Abstractions;
using OtpNet;
using System.Text.Json;
using Xunit;

namespace CompAuthApi.Tests;

public sealed class AuthenticatorRecoveryTests
{
    private const string Secret = "JBSWY3DPEHPK3PXP";
    private const string NewPassword = "Updated-Pass-123!";

    [Fact]
    public void MigrationOnlyCreatesRecoveryTablesAndIndex()
    {
        var migration = new AddAuthenticatorPasswordRecovery { ActiveProvider = "Microsoft.EntityFrameworkCore.SqlServer" };
        Assert.Equal(4, migration.UpOperations.Count);
        Assert.Equal(new[] { "AuthenticatorActionGrants", "AuthenticatorUsedSteps", "PasswordRecoveryThrottles" },
            migration.UpOperations.OfType<CreateTableOperation>().Select(t => t.Name));
        Assert.IsType<CreateIndexOperation>(migration.UpOperations.Last());
        Assert.All(migration.DownOperations, operation => Assert.IsType<DropTableOperation>(operation));
    }
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
        public string Code => new Totp(Base32Encoding.ToBytes(Secret)).ComputeTotp(Now.UtcDateTime);
    }
    private static async Task<MobileAccessPolicyTests.Fixture> Prepare()
    {
        var f = await MobileAccessPolicyTests.Fixture.Create();
        var user = await f.Db.Users.Include(u => u.UserSecurity).SingleAsync(u => u.Id == 42);
        user.Password = BCrypt.Net.BCrypt.HashPassword("Original-Password", 4);
        user.UserSecurity.IsTwoFactorEnabled = true;
        user.UserSecurity.TwoFactorSecretKey = Secret;
        user.UserSecurity.RefreshToken = "old-refresh";
        user.UserSecurity.PasswordResetToken = "old-email-code";
        user.UserSecurity.PasswordResetTokenExpiry = DateTimeOffset.UtcNow.AddHours(1);
        await f.Db.SaveChangesAsync();
        return f;
    }

    [Fact]
    public async Task ApprovedReenrollmentPersistsAndRotatesOnlyAfterCodeOnRequestingDevice()
    {
        await using var f = await Prepare();
        var clock = new Clock();
        var service = new AuthenticatorRecoveryService(f.Db, clock);
        var protector = new EphemeralDataProtectionProvider().CreateProtector("recovery-test");
        const string key = "password-issued-challenge";
        const string device = "requesting-device";
        f.Db.UserSessions.Add(new UserSession { UserId = 42, SessionId = "old-session", DeviceId = device, IsActive = true });
        var mobileDevice = new MobileDevice
        {
            Id = Guid.NewGuid(), TargetAuthUserId = 42, InstallationId = device, Platform = "ios",
            PublicKeyPem = "public-key", Status = DeviceRegistrationStatus.Approved
        };
        f.Db.MobileDevices.Add(mobileDevice);
        f.Db.DeviceSessions.Add(new DeviceSession
        {
            Id = Guid.NewGuid(), AuthUserId = 42, MobileDeviceId = mobileDevice.Id,
            CompAuthSessionId = "old-session", TokenHash = "old-mobile-token"
        });
        await f.Db.SaveChangesAsync();

        Assert.Equal(409, (await service.RequestReenrollmentAsync(42, "user42", device, key, "older-key")).HttpStatus);
        var requested = await service.RequestReenrollmentAsync(42, "user42", device, key, key);
        Assert.Equal("requested", requested.Status);
        Assert.True((await service.RequestReenrollmentAsync(42, "user42@example.test", device, "new-challenge", key)).AlreadyRequested);
        var differentDevice = await service.RequestReenrollmentAsync(42, "user42", "other-device", "its-challenge", "its-challenge");
        Assert.True(differentDevice.AlreadyRequested);
        Assert.Null(differentDevice.RequestId);
        var stored = await f.Db.AuthenticatorReenrollments.AsNoTracking().SingleAsync();
        Assert.Equal(AuthenticatorRecoveryService.Hash(key), stored.RequestKeyHash);
        Assert.Equal(403, (await service.PrepareReenrollmentAsync(42, "user42", device, key, protector)).HttpStatus);

        clock.Now = clock.Now.AddDays(30);
        var approved = await service.SetReenrollmentDecisionAsync(42, requested.RequestId!.Value, 10, approve: true);
        Assert.Equal("approved", approved.Status);
        clock.Now = clock.Now.AddDays(30);
        Assert.False((await service.ReadReenrollmentAsync(42, "user42", "other-device", key)).CanContinue);
        Assert.False((await service.ReadReenrollmentAsync(42, "user42", device, "wrong-key")).CanContinue);
        Assert.True((await service.ReadReenrollmentAsync(42, "user42", device, key)).CanContinue);
        Assert.Equal(403, (await service.PrepareReenrollmentAsync(42, "user42", "other-device", key, protector)).HttpStatus);
        var setup = await service.PrepareReenrollmentAsync(42, "user42", device, key, protector);
        Assert.NotNull(setup.Setup);
        Assert.NotEqual(Secret, setup.Setup.Secret);
        Assert.Equal(setup.Setup.Secret, (await service.PrepareReenrollmentAsync(42, "user42", device, key, protector)).Setup?.Secret);
        Assert.Equal(Secret, (await f.Db.UserSecurities.AsNoTracking().SingleAsync(s => s.UserId == 42)).TwoFactorSecretKey);
        Assert.Equal("invalid_recovery_otp", (await service.CompleteReenrollmentAsync(42, "user42", device, key, "invalid", protector)).Code);

        var newTotp = new Totp(Base32Encoding.ToBytes(setup.Setup.Secret));
        var code = newTotp.ComputeTotp(clock.Now.UtcDateTime);
        Assert.Equal("completed", (await service.CompleteReenrollmentAsync(42, "user42", device, key, code, protector)).Status);
        Assert.Equal("completed", (await service.CompleteReenrollmentAsync(42, "user42", device, key, code, protector)).Status);
        Assert.Equal(403, (await service.CompleteReenrollmentAsync(42, "user42", "other-device", key, code, protector)).HttpStatus);
        Assert.False(await service.ConsumeLoginCodeAsync(42, code, false));
        clock.Now = clock.Now.AddMinutes(2);
        Assert.True(await service.ConsumeLoginCodeAsync(42, newTotp.ComputeTotp(clock.Now.UtcDateTime), false));
        var security = await f.Db.UserSecurities.AsNoTracking().SingleAsync(s => s.UserId == 42);
        Assert.Equal(setup.Setup.Secret, security.TwoFactorSecretKey);
        Assert.True(security.IsTwoFactorEnabled);
        Assert.False((await f.Db.UserSessions.AsNoTracking().SingleAsync()).IsActive);
        Assert.NotNull((await f.Db.DeviceSessions.AsNoTracking().SingleAsync()).RevokedAt);
        stored = await f.Db.AuthenticatorReenrollments.AsNoTracking().SingleAsync();
        Assert.Equal(10, stored.ApprovedByAuthUserId);
        Assert.Null(stored.ProtectedSetupSecret);
        Assert.Equal("completed", (await service.SetReenrollmentDecisionAsync(42, stored.Id, 11, approve: false)).Status);
    }

    [Fact]
    public async Task CancelledRecoveryAllowsNewRequestFromAnotherDevice()
    {
        await using var f = await Prepare();
        var service = new AuthenticatorRecoveryService(f.Db, new Clock());
        var requested = await service.RequestReenrollmentAsync(42, "user42", "original", "key-1", "key-1");
        await service.SetReenrollmentDecisionAsync(42, requested.RequestId!.Value, 10, approve: true);
        Assert.Equal("cancelled", (await service.SetReenrollmentDecisionAsync(42, requested.RequestId.Value, 11, approve: false)).Status);
        Assert.False((await service.ReadReenrollmentAsync(42, "user42", "original", "key-1")).CanContinue);
        var replacement = await service.RequestReenrollmentAsync(42, "user42", "replacement", "key-2", "key-2");
        Assert.Equal("requested", replacement.Status);
        Assert.NotEqual(requested.RequestId, replacement.RequestId);
        Assert.False(replacement.AlreadyRequested);
    }

    [Theory]
    [InlineData("user42")]
    [InlineData(" USER42@EXAMPLE.TEST ")]
    public async Task UsernameAndEmailIssueHashedSingleUseGrantAndPreserveAuthenticator(string login)
    {
        await using var f = await Prepare();
        var clock = new Clock();
        var service = new AuthenticatorRecoveryService(f.Db, clock);
        f.Db.UserSessions.Add(new UserSession { UserId = 42, SessionId = "old-session", DeviceId = "phone", RefreshToken = "session-refresh" });
        f.Db.MobileDevices.Add(new MobileDevice { Id = Guid.NewGuid(), TargetAuthUserId = 42, InstallationId = "test-phone", Platform = "ios", PublicKeyPem = "public-key", Status = DeviceRegistrationStatus.Approved });
        await f.Db.SaveChangesAsync();
        var device = await f.Db.MobileDevices.SingleAsync();
        f.Db.DeviceSessions.Add(new DeviceSession { Id = Guid.NewGuid(), AuthUserId = 42, MobileDeviceId = device.Id, CompAuthSessionId = "old-session", TokenHash = "old-mobile-token" });
        await f.Db.SaveChangesAsync();
        var verified = await service.VerifyAsync(login, clock.Code, "test-ip");
        Assert.True(verified.Success);
        var grant = await f.Db.AuthenticatorActionGrants.AsNoTracking().SingleAsync();
        Assert.Equal(AuthenticatorRecoveryService.Hash(verified.Token!), grant.TokenHash);
        Assert.NotEqual(verified.Token, grant.TokenHash);
        Assert.Equal(clock.Now.UtcDateTime.AddMinutes(5), grant.ExpiresUtc);
        Assert.True((await service.CompleteAsync(verified.Token, NewPassword, NewPassword)).Success);
        Assert.False((await service.CompleteAsync(verified.Token, "Another-Pass-456!", "Another-Pass-456!")).Success);
        f.Db.ChangeTracker.Clear();
        var user = await f.Db.Users.Include(u => u.UserSecurity).SingleAsync(u => u.Id == 42);
        Assert.True(BCrypt.Net.BCrypt.Verify(NewPassword, user.Password));
        Assert.Equal(Secret, user.UserSecurity.TwoFactorSecretKey);
        Assert.True(user.UserSecurity.IsTwoFactorEnabled);
        Assert.Null(user.UserSecurity.PasswordResetToken);
        Assert.Null(user.UserSecurity.RefreshToken);
        Assert.False((await f.Db.UserSessions.SingleAsync()).IsActive);
        Assert.Null((await f.Db.UserSessions.SingleAsync()).RefreshToken);
        Assert.NotNull((await f.Db.DeviceSessions.SingleAsync()).RevokedAt);
    }

    [Fact]
    public async Task InvalidOrExpiredAuthorizationCannotChangePassword()
    {
        await using var f = await Prepare();
        var clock = new Clock(); var service = new AuthenticatorRecoveryService(f.Db, clock);
        Assert.False((await service.CompleteAsync("old-email-code", NewPassword, NewPassword)).Success);
        var grant = await service.VerifyAsync("user42", clock.Code, "ip");
        Assert.Equal("invalid_new_password", (await service.CompleteAsync(grant.Token, "short", "short")).Code);
        Assert.False((await service.CompleteAsync(grant.Token, NewPassword, "different")).Success);
        clock.Now = clock.Now.AddMinutes(6);
        Assert.False((await service.CompleteAsync(grant.Token, NewPassword, NewPassword)).Success);
        f.Db.ChangeTracker.Clear();
        Assert.True(BCrypt.Net.BCrypt.Verify("Original-Password", (await f.Db.Users.SingleAsync(u => u.Id == 42)).Password));
    }

    [Fact]
    public async Task RecoveryRejectsReplayAcrossUsernameEmailAndLogin()
    {
        await using var f = await Prepare(); var clock = new Clock();
        var service = new AuthenticatorRecoveryService(f.Db, clock);
        Assert.True(await service.ConsumeLoginCodeAsync(42, clock.Code, false));
        Assert.False((await service.VerifyAsync("user42@example.test", clock.Code, "ip")).Success);
        clock.Now = clock.Now.AddSeconds(30);
        var grant = await service.VerifyAsync("user42", clock.Code, "ip");
        Assert.True(grant.Success);
        Assert.False((await service.VerifyAsync("user42@example.test", clock.Code, "another-ip")).Success);
        Assert.False(await service.ConsumeLoginCodeAsync(42, clock.Code, false));
    }

    [Fact]
    public async Task AliasesShareAttemptLimitAndWindowExpires()
    {
        await using var f = await Prepare(); var clock = new Clock();
        var service = new AuthenticatorRecoveryService(f.Db, clock);
        for (var i = 0; i < 5; i++)
        {
            var result = await service.VerifyAsync(i % 2 == 0 ? "user42" : "user42@example.test", "bad", "ip-" + i);
            Assert.Equal("invalid_recovery", result.Code);
        }
        Assert.Equal(429, (await service.VerifyAsync("user42", clock.Code, "new-ip")).Status);
        clock.Now = clock.Now.AddMinutes(16);
        Assert.True((await service.VerifyAsync("user42@example.test", clock.Code, "new-ip")).Success);
    }

    [Fact]
    public async Task UnknownDisabledAndUnenrolledAccountsHaveSameFailureAndCannotCreateGrants()
    {
        await using var f = await Prepare(); var clock = new Clock();
        var service = new AuthenticatorRecoveryService(f.Db, clock);
        Assert.Equal("invalid_recovery", (await service.VerifyAsync("missing", clock.Code, "ip")).Code);
        Assert.Equal("invalid_recovery", (await service.VerifyAsync("user43", clock.Code, "ip")).Code);
        var user = await f.Db.Users.SingleAsync(u => u.Id == 42); user.Active = false; await f.Db.SaveChangesAsync();
        Assert.Equal("invalid_recovery", (await service.VerifyAsync("user42", clock.Code, "ip")).Code);
        Assert.Empty(await f.Db.AuthenticatorActionGrants.ToListAsync());
        Assert.Null(await service.PrepareSetupAsync("user42", null));
    }

    [Fact]
    public async Task PasswordOrEnrollmentChangesInvalidatePendingReset()
    {
        await using var f = await Prepare(); var clock = new Clock();
        var service = new AuthenticatorRecoveryService(f.Db, clock);
        var grant = await service.VerifyAsync("user42", clock.Code, "ip");
        var security = await f.Db.UserSecurities.SingleAsync(s => s.UserId == 42);
        security.TwoFactorSecretKey = "JBSWY3DPEHPK3PXQ"; await f.Db.SaveChangesAsync();
        Assert.False((await service.CompleteAsync(grant.Token, NewPassword, NewPassword)).Success);
    }

    [Fact]
    public async Task SetupNeedsPasswordIssuedGrantAndCannotReplaceEnrolledSecret()
    {
        await using var f = await Prepare(); var service = new AuthenticatorRecoveryService(f.Db, new Clock());
        Assert.Null(await service.IssueSetupAsync(42));
        Assert.Null(await service.PrepareSetupAsync("user42", null));
        var grant = await service.IssueSetupAsync(43);
        Assert.NotNull(grant);
        Assert.Null(await service.PrepareSetupAsync("user43", null));
        Assert.Null(await service.PrepareSetupAsync("user42", grant));
        var setup = await service.PrepareSetupAsync("user43", grant);
        Assert.NotNull(setup);
        Assert.Equal(setup.Secret, (await service.PrepareSetupAsync("user43", grant))!.Secret);
        Assert.False((await service.CompleteAsync(grant, NewPassword, NewPassword)).Success);
        f.Db.ChangeTracker.Clear();
        Assert.Equal(Secret, (await f.Db.UserSecurities.SingleAsync(s => s.UserId == 42)).TwoFactorSecretKey);
    }

    [Fact]
    public async Task LegacyEmailAndResetRoutesAreDisabled()
    {
        await using var f = await Prepare();
        foreach (var result in new[] {
            await AuthEndpoints.ForgotPassword(f.Db, new ForgotPasswordDto { Email = "user42@example.test" }),
            await AuthEndpoints.CustomerForgotPassword(f.Db, new ForgotPasswordDto { Email = "user42@example.test" }),
            await AuthEndpoints.ResetPassword(f.Db, new ResetPasswordDto { PasswordToken = "old-email-code", Password = NewPassword, ConfirmPassword = NewPassword }) })
            Assert.Equal(410, ((IStatusCodeHttpResult)result).StatusCode);
        f.Db.ChangeTracker.Clear();
        Assert.Equal("old-email-code", (await f.Db.UserSecurities.SingleAsync(s => s.UserId == 42)).PasswordResetToken);
    }

    [Fact]
    public async Task EndpointsReturnNoStoreAuthorizationAndRequireItForCompletion()
    {
        await using var f = await Prepare();
        var context = new DefaultHttpContext();
        var logger = NullLogger<PasswordRecoveryEndpoints>.Instance;
        var code = new Totp(Base32Encoding.ToBytes(Secret)).ComputeTotp();
        var result = await PasswordRecoveryEndpoints.Verify(new("USER42@EXAMPLE.TEST", code), f.Db, context, logger);
        Assert.Equal(200, ((IStatusCodeHttpResult)result).StatusCode);
        Assert.Equal("no-store", context.Response.Headers.CacheControl);
        var json = JsonSerializer.SerializeToElement(((IValueHttpResult)result).Value);
        var raw = json.GetProperty("resetToken").GetString();
        Assert.Equal(64, raw!.Length);
        var completed = await PasswordRecoveryEndpoints.Complete(new(raw, NewPassword, NewPassword), f.Db, context, logger);
        Assert.Equal(200, ((IStatusCodeHttpResult)completed).StatusCode);
        Assert.Equal(400, ((IStatusCodeHttpResult)await PasswordRecoveryEndpoints.Complete(new(raw, NewPassword, NewPassword), f.Db, context, logger)).StatusCode);
    }

    [Fact]
    public async Task RateLimitAlsoAppliesAcrossAccountsFromOneIp()
    {
        await using var f = await Prepare(); var service = new AuthenticatorRecoveryService(f.Db, new Clock());
        for (var i = 0; i < 30; i++)
            Assert.Equal(400, (await service.VerifyAsync("unknown-" + i, "123456", "shared-ip")).Status);
        Assert.Equal(429, (await service.VerifyAsync("user42", new Clock().Code, "shared-ip")).Status);
        Assert.Empty(await f.Db.AuthenticatorActionGrants.ToListAsync());
    }

    [Fact]
    public async Task ConcurrentCompletionConsumesGrantExactlyOnce()
    {
        var file = Path.Combine(Path.GetTempPath(), "comp-auth-recovery-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<CompAuthApiDbContext>().UseSqlite($"Data Source={file};Pooling=False").Options;
            await using var db = new CompAuthApiDbContext(options);
            await db.Database.EnsureCreatedAsync();
            db.Roles.Add(new Role { Id = 1, TitleLT = "Maker" });
            db.Users.Add(new User { Id = 42, Username = "user42", Email = "user42@example.test", Password = "hash", RoleId = 1, Active = true,
                UserSecurity = new UserSecurity { IsTwoFactorEnabled = true, TwoFactorSecretKey = Secret } });
            await db.SaveChangesAsync();
            var service = new AuthenticatorRecoveryService(db, new Clock());
            var grant = await service.VerifyAsync("user42", new Clock().Code, "ip");
            var results = await Task.WhenAll(
                Task.Run(() => service.CompleteAsync(grant.Token, NewPassword, NewPassword)),
                Task.Run(() => service.CompleteAsync(grant.Token, "Other-Password-123!", "Other-Password-123!")));
            Assert.Single(results.Where(r => r.Success));
        }
        finally { if (File.Exists(file)) File.Delete(file); }
    }
}
