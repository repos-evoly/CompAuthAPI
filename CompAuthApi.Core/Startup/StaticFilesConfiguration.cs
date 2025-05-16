using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.FileProviders;

namespace CompAuthApi.Core.Startup
{
  public static class StaticFilesConfiguration
  {
    public static WebApplication ConfigureStaticFiles(this WebApplication app)
    {
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