using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.FileProviders;

namespace CompAuthApi.Core.Startup
{
  public static class StaticFilesConfiguration
  {
    public static WebApplication ConfigureStaticFiles(this WebApplication app)
    {
      // Old enrollment QR images contain authenticator secrets. New enrollment
      // returns an inline image only after a password-verified challenge.
      app.Use(async (context, next) =>
      {
        if (context.Request.Path.StartsWithSegments("/Attachments", StringComparison.OrdinalIgnoreCase) &&
            (context.Request.Path.Value?.EndsWith("_2FA.png", StringComparison.OrdinalIgnoreCase) ?? false))
        {
          context.Response.StatusCode = 404;
          return;
        }
        if (context.Request.Path.StartsWithSegments("/api/auth", StringComparison.OrdinalIgnoreCase))
          context.Response.Headers.CacheControl = "no-store";
        await next();
      });
      app.UseFileServer(new FileServerOptions
      {
        FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "Attachments")),
        RequestPath = "/Attachments",
        EnableDefaultFiles = true
      });
      return app;
    }

  }

}
