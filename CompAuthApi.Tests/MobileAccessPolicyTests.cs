using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using CompAuthApi.Core.Devices;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Microsoft.Extensions.Options;

namespace CompAuthApi.Tests;

public sealed class MobileAccessPolicyTests
{
    [Fact]
    public async Task MissingPolicyRequiresApproval()
    {
        await using var fixture = await Fixture.Create();
        Assert.True((await MobileAccessPolicyReader.ReadAsync(fixture.Db, default)).RequireApprovedDevice);
        await Assert.ThrowsAsync<DeviceProofRequiredException>(() => fixture.PasswordLogin());
    }

    [Fact]
    public async Task PasswordLoginCreatesUnapprovedInstallationAndPolicyOnBlocksItsSession()
    {
        await using var fixture = await Fixture.Create();
        await fixture.SetPolicy(false);
        var response = await fixture.PasswordLogin();
        var token = response.GetProperty("deviceSessionToken").GetString()!;
        var session = await fixture.Service.ValidateSessionAsync(token, 42, default);
        var device = await fixture.Db.MobileDevices.SingleAsync();
        Assert.Equal(DeviceRegistrationStatus.Pending, device.Status);
        Assert.Null(device.ProofVerifiedAt);
        Assert.False((await fixture.Db.DeviceSessions.SingleAsync()).ApprovedDeviceAuthenticated);
        Assert.Equal(42, session.AuthUserId);
        await Assert.ThrowsAsync<InvalidDeviceSessionException>(() => fixture.Service.ValidateSessionAsync(token, 43, default));
        await fixture.SetPolicy(true);
        await Assert.ThrowsAsync<InvalidDeviceSessionException>(() => fixture.Service.ValidateSessionAsync(token, 42, default));
        // Even administratively changing approval cannot upgrade this session's assurance.
        device.Status = DeviceRegistrationStatus.Approved;
        await fixture.Db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidDeviceSessionException>(() => fixture.Service.ValidateSessionAsync(token, 42, default));
        await fixture.SetPolicy(false);
        await fixture.Service.ValidateSessionAsync(token, 42, default);
        device.Status = DeviceRegistrationStatus.Revoked;
        await fixture.Db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidDeviceSessionException>(() => fixture.Service.ValidateSessionAsync(token, 42, default));
    }

    [Fact]
    public async Task ApprovedSessionSurvivesBothPolicyModes()
    {
        await using var fixture = await Fixture.Create();
        var device = new MobileDevice { Id = Guid.NewGuid(), InstallationId = "enrolled",
            TargetAuthUserId = 42, CompanyCode = "company-a", Status = DeviceRegistrationStatus.Approved };
        fixture.Db.MobileDevices.Add(device);
        fixture.Db.DeviceSessions.Add(new DeviceSession {
            Id = Guid.NewGuid(), MobileDeviceId = device.Id, AuthUserId = 42,
            TokenHash = DeviceSecurityService.HashSecret("approved-token"),
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
        });
        await fixture.Db.SaveChangesAsync();
        foreach (var required in new[] { true, false, true })
        {
            await fixture.SetPolicy(required);
            await fixture.Service.ValidateSessionAsync("approved-token", 42, default);
        }
    }

    [Fact]
    public async Task FailedLoginOrTwoFactorChallengeDoesNotRegisterInstallation()
    {
        await using var fixture = await Fixture.Create();
        await fixture.SetPolicy(false);
        foreach (var result in new[] { new { message = "Rejected" }, (object)new { challengeToken = "2fa" } })
            await fixture.Service.CompletePasswordLoginAsync("phone", "ios", "user", JsonSerializer.SerializeToElement(result), default);
        Assert.Empty(await fixture.Db.MobileDevices.ToListAsync());
        Assert.Empty(await fixture.Db.DeviceSessions.ToListAsync());
    }

    [Fact]
    public async Task PasswordInstallationsDoNotAlterEnrolledDeviceOrAnotherUsersSession()
    {
        await using var fixture = await Fixture.Create();
        await fixture.SetPolicy(false);
        fixture.Db.MobileDevices.Add(new MobileDevice { Id = Guid.NewGuid(), InstallationId = "phone",
            TargetAuthUserId = 42, Status = DeviceRegistrationStatus.Approved, PublicKeyPem = "existing-key" });
        await fixture.Db.SaveChangesAsync();
        await fixture.PasswordLogin();
        await fixture.PasswordLogin(43);
        Assert.Equal(3, await fixture.Db.MobileDevices.CountAsync());
        Assert.Equal(2, await fixture.Db.DeviceSessions.CountAsync(item => item.RevokedAt == null));
        Assert.Equal("existing-key", (await fixture.Db.MobileDevices.SingleAsync(item => item.InstallationId == "phone")).PublicKeyPem);
    }

    [Fact]
    public async Task PushRegistrationWorksWithoutApprovalButCannotTargetWhenPolicyEnabled()
    {
        await using var fixture = await Fixture.Create();
        await fixture.SetPolicy(false);
        await fixture.PasswordLogin();
        var device = await fixture.Db.MobileDevices.SingleAsync();
        var pushes = new MobilePushTokenService(fixture.Db, fixture.Options, TimeProvider.System);
        await pushes.RegisterAsync(42, new MobilePushTokenRegistrationRequest(device.Id,
            "a-valid-firebase-token-for-test", "ios", "1"), default);
        Assert.Single(await pushes.ResolveTargetsAsync([42], default));
        await fixture.SetPolicy(true);
        Assert.Empty(await pushes.ResolveTargetsAsync([42], default));
        await Assert.ThrowsAsync<PushDeviceNotApprovedException>(() => pushes.RegisterAsync(42,
            new MobilePushTokenRegistrationRequest(device.Id, "a-valid-firebase-token-for-test", "ios", "1"), default));
    }

    internal sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection connection;
        public TestDb Db { get; }
        public IOptionsMonitor<DeviceSecurityOptions> Options { get; } = new Monitor();
        public DeviceSecurityService Service { get; }
        private Fixture(SqliteConnection connection, TestDb db)
        {
            this.connection = connection; Db = db;
            Service = new DeviceSecurityService(db, new DeviceAttestationValidator(Options), Options, TimeProvider.System);
        }
        public static async Task<Fixture> Create()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new TestDb(new DbContextOptionsBuilder<CompAuthApiDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.Roles.Add(new Role { Id = 1, TitleLT = "Maker" });
            foreach (var id in new[] { 42, 43 })
                db.Users.Add(new User { Id = id, Username = $"user{id}", Email = $"user{id}@example.test",
                    Active = true, RoleId = 1, UserSecurity = new UserSecurity() });
            await db.SaveChangesAsync();
            return new Fixture(connection, db);
        }
        public async Task SetPolicy(bool required)
        {
            var settings = await Db.Settings.SingleOrDefaultAsync(item => item.Id == 1);
            if (settings is null) { settings = new Settings { Id = 1 }; Db.Settings.Add(settings); }
            settings.RequireApprovedMobileDevice = required;
            await Db.SaveChangesAsync();
        }
        public Task<JsonElement> PasswordLogin(int user = 42)
        {
            var jwt = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
                claims: [new Claim("nameid", user.ToString())]));
            return Service.CompletePasswordLoginAsync("phone", "ios", "user", JsonSerializer.SerializeToElement(new {
                accessToken = jwt, sessionId = "session", sessionExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
            }), default);
        }
        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class Monitor : IOptionsMonitor<DeviceSecurityOptions>
    {
        public DeviceSecurityOptions CurrentValue { get; } = new() { Enabled = true };
        public DeviceSecurityOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<DeviceSecurityOptions, string?> listener) => null;
    }
    public sealed class TestDb(DbContextOptions<CompAuthApiDbContext> options) : CompAuthApiDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // SQLite has no native ordered DateTimeOffset operations; use UTC ticks for tests.
            foreach (var entity in builder.Model.GetEntityTypes())
                foreach (var property in entity.GetProperties())
                    if (property.ClrType == typeof(DateTimeOffset) || property.ClrType == typeof(DateTimeOffset?))
                        property.SetValueConverter(new DateTimeOffsetToBinaryConverter());
        }
    }
}
