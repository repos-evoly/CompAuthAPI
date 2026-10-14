using System.Security.Claims;
using CompAuthApi.Data.Context;
using CompAuthApi.Endpoints;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace CompAuthApi.Tests;

public sealed class MobileAppUpdatePolicyTests
{
    [Fact]
    public async Task AdminUpdatesOnePlatformWithAuditAndRejectsStaleRevision()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        await using var db = new CompAuthApiDbContext(new DbContextOptionsBuilder<CompAuthApiDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var context = Context("Admin");
        var request = new UpdateMobileAppPolicy(true, "1.10.0", "12", AndroidUrl, "Update", "تحديث", 1);
        var result = await MobileAppUpdatePolicyEndpoints.Update("android", request, db, context, NullLogger<MobileAppUpdatePolicyEndpoints>.Instance);
        Assert.Equal(200, ((IStatusCodeHttpResult)result).StatusCode);
        var android = await db.MobileAppUpdatePolicies.AsNoTracking().SingleAsync(p => p.Platform == "android");
        Assert.True(android.Enabled);
        Assert.Equal(2, android.Revision);
        Assert.Equal("42", android.UpdatedBy);
        Assert.NotNull(android.UpdatedAt);
        Assert.False((await db.MobileAppUpdatePolicies.AsNoTracking().SingleAsync(p => p.Platform == "ios")).Enabled);
        result = await MobileAppUpdatePolicyEndpoints.Update("android", request with { MinimumVersion = "2.0.0" }, db, context, NullLogger<MobileAppUpdatePolicyEndpoints>.Instance);
        Assert.Equal(409, ((IStatusCodeHttpResult)result).StatusCode);
        Assert.Equal("1.10.0", (await db.MobileAppUpdatePolicies.AsNoTracking().SingleAsync(p => p.Platform == "android")).MinimumVersion);
    }

    [Theory]
    [InlineData("CompanyAdmin")]
    [InlineData("Maker")]
    [InlineData("")]
    public async Task NonAdminsCannotReadOrWrite(string role)
    {
        await using var db = new CompAuthApiDbContext();
        var context = Context(role);
        Assert.Equal(403, ((IStatusCodeHttpResult)await MobileAppUpdatePolicyEndpoints.ReadAdmin(db, context)).StatusCode);
        Assert.Equal(403, ((IStatusCodeHttpResult)await MobileAppUpdatePolicyEndpoints.Update("android",
            new(true, "1.0.0", "0", AndroidUrl, "Update", "تحديث", 1), db, context,
            NullLogger<MobileAppUpdatePolicyEndpoints>.Instance)).StatusCode);
    }

    [Theory]
    [InlineData("android", "https://play.google.com/store/apps/details?id=com.bcd.companygateway", true)]
    [InlineData("android", "https://play.google.com/store/apps/details?id=other.app", false)]
    [InlineData("android", "https://play.google.com.evil.test/store/apps/details?id=com.bcd.companygateway", false)]
    [InlineData("android", "https://evil@play.google.com/store/apps/details?id=com.bcd.companygateway", false)]
    [InlineData("ios", "https://apps.apple.com/ly/app/company-gateway/id123456789", true)]
    [InlineData("ios", "https://apps.apple.com/app/id123456789", true)]
    [InlineData("ios", "https://apps.apple.com/", false)]
    [InlineData("ios", "http://apps.apple.com/app/id123456789", false)]
    public void OnlyValidOfficialListingsAreAccepted(string platform, string url, bool valid) =>
        Assert.Equal(valid, MobileAppUpdatePolicyEndpoints.ValidStoreUrl(platform, url));

    [Fact]
    public async Task InvalidAndMissingFieldsNeverChangeDatabase()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        await using var db = new CompAuthApiDbContext(new DbContextOptionsBuilder<CompAuthApiDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var valid = new UpdateMobileAppPolicy(true, "1.0.0", "0", AndroidUrl, "Update", "تحديث", 1);
        foreach (var invalid in new[] { valid with { MinimumVersion = "1.0" }, valid with { MinimumVersion = "1.0.0-beta" },
            valid with { MinimumBuild = "-1" }, valid with { StoreUrl = "" }, valid with { Enabled = null },
            valid with { Revision = null }, valid with { MessageAr = "" } })
        {
            var result = await MobileAppUpdatePolicyEndpoints.Update("android", invalid, db, Context("Admin"), NullLogger<MobileAppUpdatePolicyEndpoints>.Instance);
            Assert.Equal(400, ((IStatusCodeHttpResult)result).StatusCode);
        }
        Assert.All(await db.MobileAppUpdatePolicies.ToListAsync(), p => { Assert.False(p.Enabled); Assert.Equal(1, p.Revision); });
    }

    private const string AndroidUrl = "https://play.google.com/store/apps/details?id=com.bcd.companygateway";
    private static DefaultHttpContext Context(string role) => new()
    {
        User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, "42"), new Claim(ClaimTypes.Role, role)], "test"))
    };
}
