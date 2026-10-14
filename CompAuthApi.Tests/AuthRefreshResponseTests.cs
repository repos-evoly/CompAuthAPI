using System.Text;
using System.Text.Json;
using CompAuthApi.Core.Startup;
using Microsoft.AspNetCore.Http;

namespace CompAuthApi.Tests;

public sealed class AuthRefreshResponseTests
{
    [Theory]
    [InlineData("/api/auth/refresh-token", 401)]
    [InlineData("/api/auth/refresh-token/", 400)]
    [InlineData("/api/auth/refresh-token", 500)]
    [InlineData("/api/mobile-auth/refresh-token", 401)]
    [InlineData("/api/settings/mobile-app-updates", 403)]
    public async Task AuthRefreshAndMobilePolicyFailuresKeepRealStatus(string path, int status)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        var body = "{\"detail\":\"test failure\"}";
        var middleware = new Always200ResponseMiddleware(async ctx =>
        {
            ctx.Response.StatusCode = status;
            await ctx.Response.WriteAsync(body);
        });
        await middleware.Invoke(context);
        Assert.Equal(status, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        Assert.Equal(body, await new StreamReader(context.Response.Body, Encoding.UTF8).ReadToEndAsync());
    }

    [Fact]
    public async Task SuccessfulRefreshBodyIsUnchanged()
    {
        var context = new DefaultHttpContext(); context.Request.Path = "/api/auth/refresh-token";
        context.Response.Body = new MemoryStream();
        var body = "{\"accessToken\":\"test-access\",\"refreshToken\":\"test-refresh\"}";
        await new Always200ResponseMiddleware(ctx => ctx.Response.WriteAsync(body)).Invoke(context);
        Assert.Equal(200, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        Assert.Equal(body, await new StreamReader(context.Response.Body).ReadToEndAsync());
    }

    [Fact]
    public async Task UnrelatedLegacyEndpointStillUsesItsExistingWrapper()
    {
        var context = new DefaultHttpContext(); context.Request.Path = "/api/legacy-example";
        context.Response.Body = new MemoryStream();
        await new Always200ResponseMiddleware(ctx => { ctx.Response.StatusCode = 400; return Task.CompletedTask; }).Invoke(context);
        Assert.Equal(200, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        using var body = await JsonDocument.ParseAsync(context.Response.Body);
        Assert.False(body.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(400, body.RootElement.GetProperty("status").GetInt32());
    }
}
