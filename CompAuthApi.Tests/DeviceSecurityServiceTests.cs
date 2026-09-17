using System.Security.Cryptography;
using System.Text;
using CompAuthApi.Core.Devices;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CompAuthApi.Tests;

public sealed class DeviceSecurityServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 17, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CreateEnrollmentChallenge_AllowsMatchingPendingDeviceToResume()
    {
        await using var fixture = await DeviceSecurityFixture.CreateAsync();
        using var key = RSA.Create(2048);
        var request = CreateRequest("activation-one", key);
        fixture.AddActivation("activation-one");
        await fixture.Db.SaveChangesAsync();

        var first = await fixture.Service.CreateEnrollmentChallengeAsync(
            request,
            CancellationToken.None);
        fixture.Db.ChangeTracker.Clear();
        var second = await fixture.Service.CreateEnrollmentChallengeAsync(
            request,
            CancellationToken.None);
        fixture.Db.ChangeTracker.Clear();

        Assert.Equal(first.DeviceId, second.DeviceId);
        Assert.NotEqual(first.ChallengeId, second.ChallengeId);
        Assert.Single(await fixture.Db.MobileDevices.ToArrayAsync());

        var challenges = await fixture.Db.DeviceChallenges.ToArrayAsync();
        Assert.Equal(2, challenges.Length);
        Assert.NotNull(challenges.Single(challenge => challenge.Id == first.ChallengeId).UsedAt);
        Assert.Null(challenges.Single(challenge => challenge.Id == second.ChallengeId).UsedAt);
    }

    [Fact]
    public async Task CreateEnrollmentChallenge_AllowsReplacementCodeForSameIdentity()
    {
        await using var fixture = await DeviceSecurityFixture.CreateAsync();
        using var key = RSA.Create(2048);
        var firstRequest = CreateRequest("activation-one", key);
        fixture.AddActivation("activation-one", expiresAt: Now.AddMinutes(1));
        await fixture.Db.SaveChangesAsync();
        var first = await fixture.Service.CreateEnrollmentChallengeAsync(
            firstRequest,
            CancellationToken.None);
        fixture.Db.ChangeTracker.Clear();

        fixture.Time.UtcNow = Now.AddMinutes(2);
        fixture.AddActivation("activation-two", expiresAt: Now.AddMinutes(10));
        await fixture.Db.SaveChangesAsync();

        var resumed = await fixture.Service.CreateEnrollmentChallengeAsync(
            CreateRequest("activation-two", key),
            CancellationToken.None);

        Assert.Equal(first.DeviceId, resumed.DeviceId);
        Assert.Equal(
            resumed.DeviceId,
            await fixture.Db.DeviceActivationCodes
                .Where(code => code.CodeHash == DeviceSecurityService.HashSecret("activation-two"))
                .Select(code => code.UsedByDeviceId)
                .SingleAsync());
    }

    [Fact]
    public async Task CreateEnrollmentChallenge_RejectsResumeWithDifferentKey()
    {
        await using var fixture = await DeviceSecurityFixture.CreateAsync();
        using var originalKey = RSA.Create(2048);
        using var differentKey = RSA.Create(2048);
        fixture.AddActivation("activation-one");
        await fixture.Db.SaveChangesAsync();
        await fixture.Service.CreateEnrollmentChallengeAsync(
            CreateRequest("activation-one", originalKey),
            CancellationToken.None);
        fixture.Db.ChangeTracker.Clear();

        fixture.AddActivation("activation-two");
        await fixture.Db.SaveChangesAsync();

        await Assert.ThrowsAsync<DeviceEnrollmentConflictException>(() =>
            fixture.Service.CreateEnrollmentChallengeAsync(
                CreateRequest("activation-two", differentKey),
                CancellationToken.None));
    }

    [Fact]
    public async Task CompleteEnrollment_ChangesStatusFromProofToAdministratorApproval()
    {
        await using var fixture = await DeviceSecurityFixture.CreateAsync(
            autoApprove: false);
        using var key = RSA.Create(2048);
        fixture.AddActivation("activation-one");
        await fixture.Db.SaveChangesAsync();
        var request = CreateRequest("activation-one", key);
        var challenge = await fixture.Service.CreateEnrollmentChallengeAsync(
            request,
            CancellationToken.None);

        var awaitingProof = await fixture.Service.GetStatusAsync(
            request.InstallationId,
            CancellationToken.None);
        Assert.Equal("awaiting_device_proof", awaitingProof.EnrollmentState);
        Assert.False(awaitingProof.ProofVerified);

        var payload = Encoding.UTF8.GetBytes(DeviceProofVerifier.BuildPayload(
            DeviceSecurityService.EnrollmentPurpose,
            challenge.ChallengeId,
            challenge.Nonce,
            request.InstallationId));
        var signature = Convert.ToBase64String(key.SignData(
            payload,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));

        await fixture.Service.CompleteEnrollmentAsync(
            new DeviceEnrollmentRequest(challenge.ChallengeId, signature),
            CancellationToken.None);

        var awaitingApproval = await fixture.Service.GetStatusAsync(
            request.InstallationId,
            CancellationToken.None);
        Assert.Equal("awaiting_administrator_approval", awaitingApproval.EnrollmentState);
        Assert.True(awaitingApproval.ProofVerified);
    }

    [Fact]
    public async Task CompleteEnrollment_InvalidSignatureRemainsAwaitingProof()
    {
        await using var fixture = await DeviceSecurityFixture.CreateAsync();
        using var key = RSA.Create(2048);
        fixture.AddActivation("activation-one");
        await fixture.Db.SaveChangesAsync();
        var request = CreateRequest("activation-one", key);
        var challenge = await fixture.Service.CreateEnrollmentChallengeAsync(
            request,
            CancellationToken.None);

        await Assert.ThrowsAsync<InvalidDeviceProofException>(() =>
            fixture.Service.CompleteEnrollmentAsync(
                new DeviceEnrollmentRequest(
                    challenge.ChallengeId,
                    Convert.ToBase64String(RandomNumberGenerator.GetBytes(256))),
                CancellationToken.None));

        var status = await fixture.Service.GetStatusAsync(
            request.InstallationId,
            CancellationToken.None);
        Assert.Equal("awaiting_device_proof", status.EnrollmentState);
        Assert.False(status.ProofVerified);
    }

    private static DeviceEnrollmentChallengeRequest CreateRequest(
        string activationCode,
        RSA key) =>
        new(
            activationCode,
            "installation-01",
            "ios",
            "1.0.0",
            DeviceProofVerifier.RsaSha256,
            key.ExportSubjectPublicKeyInfoPem(),
            null,
            null);

    private sealed class DeviceSecurityFixture : IAsyncDisposable
    {
        private const int TargetAuthUserId = 42;
        private const string Login = "user@company.ly";
        private const string CompanyCode = "COMPANY";

        private readonly SqliteConnection _connection;

        private DeviceSecurityFixture(
            SqliteConnection connection,
            CompAuthApiDbContext db,
            DeviceSecurityService service,
            MutableTimeProvider time)
        {
            _connection = connection;
            Db = db;
            Service = service;
            Time = time;
        }

        public CompAuthApiDbContext Db { get; }
        public DeviceSecurityService Service { get; }
        public MutableTimeProvider Time { get; }

        public static async Task<DeviceSecurityFixture> CreateAsync(
            bool autoApprove = false)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<CompAuthApiDbContext>()
                .UseSqlite(connection)
                .Options;
            var db = new CompAuthApiDbContext(options);
            await db.Database.EnsureCreatedAsync();
            var deviceOptions = new DeviceSecurityOptions
            {
                Enabled = true,
                AutoApproveWithActivationCode = autoApprove,
                EnrollmentChallengeLifetimeSeconds = 300
            };
            var monitor = new StaticOptionsMonitor<DeviceSecurityOptions>(deviceOptions);
            var time = new MutableTimeProvider(Now);
            var service = new DeviceSecurityService(
                db,
                new DeviceAttestationValidator(monitor),
                monitor,
                time);
            return new DeviceSecurityFixture(connection, db, service, time);
        }

        public void AddActivation(string rawCode, DateTimeOffset? expiresAt = null)
        {
            Db.DeviceActivationCodes.Add(new DeviceActivationCode
            {
                Id = Guid.NewGuid(),
                CodeHash = DeviceSecurityService.HashSecret(rawCode),
                TargetAuthUserId = TargetAuthUserId,
                LoginHash = DeviceSecurityService.HashLogin(Login),
                CreatedByAuthUserId = 7,
                CompanyCode = CompanyCode,
                CreatedAt = Time.UtcNow,
                ExpiresAt = expiresAt ?? Time.UtcNow.AddMinutes(30)
            });
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
