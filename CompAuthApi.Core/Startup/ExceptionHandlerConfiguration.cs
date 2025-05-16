using CompAuthApi.Core.Dtos;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Serilog;

namespace CompAuthApi.Core.Startup
{
  public static class ExceptionHandlerConfiguration
  {
    public static WebApplication ConfigureExceptionHandler(this WebApplication app)
    {
      app.UseExceptionHandler(error =>
      {
        error.Run(async context =>
        {
          context.Response.StatusCode = StatusCodes.Status500InternalServerError;
          context.Response.ContentType = "application/json";
          var contextFeature = context.Features.Get<IExceptionHandlerFeature>();
          if (contextFeature != null)
          {
            Log.Error($"Something went wrong in the {contextFeature.Error}");
            await context.Response.WriteAsync(new Error
            {
              StatusCode = context.Response.StatusCode,
              Message = "Internal server error. Please try again.",
            }.ToString());
          }
        });
      });
      return app;
    }
  }
}