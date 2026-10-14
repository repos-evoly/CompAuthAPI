using System.Security.Claims;
using System.Text.Json;
using CompAuthApi.Data.Context;
using CompAuthApi.Endpoints;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace CompAuthApi.Tests;

public sealed class MobileAppMaintenancePolicyTests
{
    [Fact]
    public async Task StartsOffAndAdminCanEnableAndRestoreWithAuditAndConcurrentSaveProtection()
    {
        using var connection = new SqliteConnection("DataSource=:memory:"); await connection.OpenAsync();
        await using var db = new CompAuthApiDbContext(new DbContextOptionsBuilder<CompAuthApiDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        Assert.False((await db.MobileAppMaintenancePolicies.SingleAsync()).Enabled);
        var request = new UpdateMobileAppMaintenancePolicy(true, " Maintenance ", " صيانة ", 1);
        var result = await Save(request, db);
        Assert.Equal(200, ((IStatusCodeHttpResult)result).StatusCode);
        var policy = await db.MobileAppMaintenancePolicies.AsNoTracking().SingleAsync();
        Assert.True(policy.Enabled); Assert.Equal(2, policy.Revision); Assert.Equal("Maintenance", policy.MessageEn);
        Assert.Equal("42", policy.UpdatedBy); Assert.NotNull(policy.UpdatedAt);
        Assert.Equal(409, ((IStatusCodeHttpResult)await Save(request with { Enabled = false }, db)).StatusCode);
        Assert.True((await db.MobileAppMaintenancePolicies.AsNoTracking().SingleAsync()).Enabled);
        Assert.Equal(200, ((IStatusCodeHttpResult)await Save(request with { Enabled = false, Revision = 2 }, db)).StatusCode);
        Assert.False((await db.MobileAppMaintenancePolicies.AsNoTracking().SingleAsync()).Enabled);
        Assert.Equal(3, (await db.MobileAppMaintenancePolicies.AsNoTracking().SingleAsync()).Revision);
        Assert.All(await db.MobileAppUpdatePolicies.ToListAsync(), p => { Assert.False(p.Enabled); Assert.Equal(1, p.Revision); });
        var publicPolicy = await MobileAppMaintenancePolicyEndpoints.Read(db, Context("Admin"));
        var json = JsonSerializer.Serialize(((IValueHttpResult)publicPolicy).Value);
        Assert.DoesNotContain("UpdatedBy", json); Assert.DoesNotContain("UpdatedAt", json);
    }

    [Theory]
    [InlineData("CompanyAdmin")]
    [InlineData("Maker")]
    [InlineData("")]
    public async Task NonAdminsCannotReadOrWrite(string role)
    {
        await using var db = new CompAuthApiDbContext();
        Assert.Equal(403, ((IStatusCodeHttpResult)await MobileAppMaintenancePolicyEndpoints.ReadAdmin(db, Context(role))).StatusCode);
        Assert.Equal(403, ((IStatusCodeHttpResult)await Save(new(true, "Maintenance", "صيانة", 1), db, role)).StatusCode);
    }

    [Fact]
    public async Task MissingOrOversizedMessagesAndInvalidRevisionCannotChangePolicy()
    {
        using var connection = new SqliteConnection("DataSource=:memory:"); await connection.OpenAsync();
        await using var db = new CompAuthApiDbContext(new DbContextOptionsBuilder<CompAuthApiDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var valid = new UpdateMobileAppMaintenancePolicy(true, "Maintenance", "صيانة", 1);
        foreach (var invalid in new[] { valid with { Enabled = null }, valid with { MessageEn = " " }, valid with { MessageAr = null },
            valid with { MessageEn = new string('x', 501) }, valid with { MessageAr = new string('x', 501) },
            valid with { Revision = null }, valid with { Revision = 0 } })
            Assert.Equal(400, ((IStatusCodeHttpResult)await Save(invalid, db)).StatusCode);
        var policy = await db.MobileAppMaintenancePolicies.SingleAsync(); Assert.False(policy.Enabled); Assert.Equal(1, policy.Revision);
    }

    private static Task<IResult> Save(UpdateMobileAppMaintenancePolicy request, CompAuthApiDbContext db, string role = "Admin") =>
        MobileAppMaintenancePolicyEndpoints.Update(request, db, Context(role), NullLogger<MobileAppMaintenancePolicyEndpoints>.Instance);
    private static DefaultHttpContext Context(string role) => new()
    {
        User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "42"), new Claim(ClaimTypes.Role, role)], "test"))
    };
}
