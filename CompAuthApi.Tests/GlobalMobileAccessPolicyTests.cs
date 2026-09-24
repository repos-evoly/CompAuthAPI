using System.Security.Claims;
using CompAuthApi.Core.Devices;
using CompAuthApi.Data.Models;
using CompAuthApi.Endpoints;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace CompAuthApi.Tests;

public sealed class GlobalMobileAccessPolicyTests
{
    [Fact]
    public async Task CompanyOverridesCannotChangeGlobalPolicyAndGlobalOnBlocksAllCompanies()
    {
        await using var f = await MobileAccessPolicyTests.Fixture.Create();
        f.Db.CompanyMobileAccessPolicies.AddRange(
            new CompanyMobileAccessPolicy { CompanyCode = "A", RequireApprovedDevice = true },
            new CompanyMobileAccessPolicy { CompanyCode = "B", RequireApprovedDevice = false });
        await f.SetPolicy(false);
        Assert.False((await f.Service.GetLoginPolicyAsync("user42", default)).RequireApprovedDevice);
        Assert.False((await f.Service.GetLoginPolicyAsync("user43", default)).RequireApprovedDevice);
        var a = (await f.PasswordLogin(42)).GetProperty("deviceSessionToken").GetString()!;
        var b = (await f.PasswordLogin(43)).GetProperty("deviceSessionToken").GetString()!;
        var devices = await f.Db.MobileDevices.OrderBy(d => d.TargetAuthUserId).ToListAsync();
        devices[0].CompanyCode = "A";
        devices[1].CompanyCode = "B";
        await f.Db.SaveChangesAsync();
        var push = new MobilePushTokenService(f.Db, f.Options, TimeProvider.System);
        foreach (var device in devices)
            await push.RegisterAsync(device.TargetAuthUserId, new MobilePushTokenRegistrationRequest(
                device.Id, $"test-firebase-token-for-user-{device.TargetAuthUserId}", "ios", "1"), default);
        Assert.Equal(2, (await push.ResolveTargetsAsync([42,43], default)).Count);
        await f.SetPolicy(true);
        Assert.True((await f.Service.GetLoginPolicyAsync("user43", default)).RequireApprovedDevice);
        await Assert.ThrowsAsync<InvalidDeviceSessionException>(() => f.Service.ValidateSessionAsync(a, 42, default));
        await Assert.ThrowsAsync<InvalidDeviceSessionException>(() => f.Service.ValidateSessionAsync(b, 43, default));
        Assert.Empty(await push.ResolveTargetsAsync([42,43], default));
        await f.SetPolicy(false);
        await f.Service.ValidateSessionAsync(a, 42, default);
        await f.Service.ValidateSessionAsync(b, 43, default);
    }

    [Theory]
    [InlineData("CompanyAdmin")]
    [InlineData("Maker")]
    [InlineData("")]
    public async Task CompanyAdminAndOrdinaryUsersCannotReadOrChangeGlobalPolicy(string role)
    {
        await using var f = await MobileAccessPolicyTests.Fixture.Create();
        await f.SetPolicy(true);
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, "42"), new Claim(ClaimTypes.Role, role),
            new Claim("isCompanyAdmin", "true")], "test")) };
        Assert.Equal(403, ((IStatusCodeHttpResult)await MobileAccessPolicyEndpoints.Read(f.Db, context)).StatusCode);
        Assert.Equal(403, ((IStatusCodeHttpResult)await MobileAccessPolicyEndpoints.Update(new(false, 1),
            f.Db, context, NullLogger<MobileAccessPolicyEndpoints>.Instance)).StatusCode);
        Assert.True((await MobileAccessPolicyReader.ReadAsync(f.Db, default)).RequireApprovedDevice);
    }
}
