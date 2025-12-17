using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

namespace CompAuthApi.Core.Startup
{
  public static class SerilogConfiguration
  {
    public static ConfigureHostBuilder ConfigureSerilog(this ConfigureHostBuilder config)
    {
      Log.CloseAndFlush();
      config.UseSerilog((hostContext, services, configuration) =>
      {
        configuration
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Environment", hostContext.HostingEnvironment.EnvironmentName)
            .WriteTo.File(
              path: "c:\\CompAuth\\logs\\log-.txt",
              outputTemplate: "---> {Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{level:u3}] {Message:1j}{Newline}",
              rollingInterval: RollingInterval.Day,
              restrictedToMinimumLevel: LogEventLevel.Information
              ).WriteTo.Console();
      });
      return config;
    }
  }
}
