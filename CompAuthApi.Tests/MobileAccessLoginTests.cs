using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using CompAuthApi.Core.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Dtos;
using CompAuthApi.Data.Models;
using CompAuthApi.Endpoints;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OtpNet;

namespace CompAuthApi.Tests;

public sealed class MobileAccessLoginTests
{
    private const string Secret = "JBSWY3DPEHPK3PXP";
    private static readonly IConfiguration Config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
        ["Jwt:Key"] = new string('x', 64), ["Jwt:Issuer"] = "test", ["Jwt:Audience"] = "test"
    }).Build();

    [Fact]
    public async Task PasswordLoginWorksWhenOffAndInvalidPasswordStillFails()
    {
        await using var f = await Prepare(false);
        using var challenges = new Challenges();
        var failed = await Login(f, challenges, "wrong-password");
        Assert.False(Json(failed).TryGetProperty("accessToken", out _));
        Assert.Empty(await f.Db.DeviceSessions.ToListAsync());
        var result = Json(await Login(f, challenges));
        Assert.False(string.IsNullOrWhiteSpace(result.GetProperty("accessToken").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(result.GetProperty("deviceSessionToken").GetString()));
        Assert.False((await f.Db.DeviceSessions.SingleAsync()).ApprovedDeviceAuthenticated);
    }

    [Fact]
    public async Task EnabledPolicyStillRejectsLoginWithoutSignedDeviceProof()
    {
        await using var f = await Prepare(true);
        using var challenges = new Challenges();
        var result = await Login(f, challenges);
        Assert.Equal(401, ((IStatusCodeHttpResult)result).StatusCode);
        Assert.Empty(await f.Db.UserSessions.ToListAsync());
        Assert.Empty(await f.Db.DeviceSessions.ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TwoFactorIsRequiredAndRechecksPolicyBeforeCompletion(bool enableDuringChallenge)
    {
        await using var f = await Prepare(false);
        var settings = await f.Db.Settings.SingleAsync();
        settings.IsTwoFactorAuthEnabled = true;
        var user = await f.Db.Users.Include(item => item.UserSecurity).SingleAsync(item => item.Id == 42);
        user.UserSecurity.IsTwoFactorEnabled = true;
        user.UserSecurity.TwoFactorSecretKey = Secret;
        await f.Db.SaveChangesAsync();
        using var challenges = new Challenges();
        var login = Json(await Login(f, challenges));
        Assert.True(login.GetProperty("requiresTwoFactor").GetBoolean());
        Assert.False(login.TryGetProperty("accessToken", out _));
        Assert.Empty(await f.Db.DeviceSessions.ToListAsync());
        if (enableDuringChallenge) await f.SetPolicy(true);
        var result = await MobileAuthEndpoints.VerifyTwoFactor(f.Db, Config, new Geo(), challenges.Service,
            f.Service, new DefaultHttpContext(), new MobileVerifyTwoFactorDto {
                Login = "user42", DeviceId = "phone", Platform = "ios",
                ChallengeToken = login.GetProperty("challengeToken").GetString()!,
                Token = new Totp(Base32Encoding.ToBytes(Secret)).ComputeTotp()
            });
        if (enableDuringChallenge)
        {
            Assert.Equal(401, ((IStatusCodeHttpResult)result).StatusCode);
            Assert.Empty(await f.Db.DeviceSessions.ToListAsync());
        }
        else Assert.True(Json(result).TryGetProperty("deviceSessionToken", out _));
    }

    [Fact]
    public async Task PolicyUpdateIsExplicitVersionedAndDoesNotChangeOtherSettings()
    {
        await using var f = await Prepare(true);
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, "7"), new Claim(ClaimTypes.Role, "Admin")], "test")) };
        var log = NullLogger<MobileAccessPolicyEndpoints>.Instance;
        var invalid = await MobileAccessPolicyEndpoints.Update(new(null, 1), f.Db, context, log);
        Assert.Equal(400, ((IStatusCodeHttpResult)invalid).StatusCode);
        var saved = await MobileAccessPolicyEndpoints.Update(new(false, 1), f.Db, context, log);
        Assert.Equal(200, ((IStatusCodeHttpResult)saved).StatusCode);
        var stale = await MobileAccessPolicyEndpoints.Update(new(true, 1), f.Db, context, log);
        Assert.Equal(409, ((IStatusCodeHttpResult)stale).StatusCode);
        f.Db.ChangeTracker.Clear();
        var settings = await f.Db.Settings.SingleAsync();
        Assert.False(settings.RequireApprovedMobileDevice);
        Assert.Equal(2, settings.MobileAccessPolicyVersion);
        Assert.Equal("7", settings.MobileAccessPolicyUpdatedBy);
        Assert.NotNull(settings.MobileAccessPolicyUpdatedAt);
        Assert.Equal(5, settings.MaxLoginAttempts);
    }

    private static async Task<MobileAccessPolicyTests.Fixture> Prepare(bool required)
    {
        var f = await MobileAccessPolicyTests.Fixture.Create();
        f.Db.Settings.Add(new Settings { Id = 1, MaxLoginAttempts = 5 });
        await f.Db.SaveChangesAsync();
        await f.SetPolicy(required);
        var user = await f.Db.Users.SingleAsync(item => item.Id == 42);
        user.Password = BCrypt.Net.BCrypt.HashPassword("correct-password", 4);
        await f.Db.SaveChangesAsync();
        return f;
    }
    private static Task<IResult> Login(MobileAccessPolicyTests.Fixture f, Challenges c, string password = "correct-password") =>
        MobileAuthEndpoints.Login(f.Db, Config, new Geo(), c.Service, f.Service,
            new DefaultHttpContext(), new MobileLoginDto { Login = "user42", Password = password, DeviceId = "phone", Platform = "ios" });
    private static JsonElement Json(IResult result) =>
        JsonSerializer.SerializeToElement(((IValueHttpResult)result).Value, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    private sealed class Challenges : IDisposable
    {
        private readonly RSA key = RSA.Create(2048);
        public ServiceTokenService Service { get; }
        public Challenges() => Service = new ServiceTokenService(new Monitor<ServiceTokenOptions>(new() {
            Issuer = "test", Audience = "test", Environment = "test",
            PrivateKeyPem = key.ExportPkcs8PrivateKeyPem(), PublicKeyPem = key.ExportSubjectPublicKeyInfoPem()
        }), TimeProvider.System);
        public void Dispose() => key.Dispose();
    }
    private sealed class Monitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
    private sealed class Geo : IGeoFenceService
    {
        public Task<GeoFenceEvaluationDto> EvaluateLoginAsync(User user, HttpContext context, DateTimeOffset now, CancellationToken cancellationToken = default) =>
            Task.FromResult(new GeoFenceEvaluationDto());
        public Task RecordLoginEventAsync(User user, GeoFenceEvaluationDto evaluation, DateTimeOffset now,
            bool isSuccessful, string? sessionId = null, string? failureCode = null, string? failureReason = null,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
