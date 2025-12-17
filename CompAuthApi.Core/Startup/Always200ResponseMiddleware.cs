using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace CompAuthApi.Core.Startup
{
  public class Always200ResponseMiddleware
  {
    private readonly RequestDelegate _next;
    private static readonly string[] _skipPrefixes = new[] { "/swagger", "/notificationHub" };

    public Always200ResponseMiddleware(RequestDelegate next)
    {
      _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
      var path = context.Request.Path.Value ?? string.Empty;
      if (_skipPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
      {
        await _next(context);
        return;
      }

      var originalBody = context.Response.Body;
      await using var memStream = new MemoryStream();
      context.Response.Body = memStream;

      try
      {
        await _next(context);

        // After downstream writes
        memStream.Position = 0;
        var status = context.Response.StatusCode;

        if (status >= 400)
        {
          var originalText = await new StreamReader(memStream, Encoding.UTF8).ReadToEndAsync();
          object? details = TryParseJson(originalText);

          var payload = new
          {
            success = false,
            status,
            message = !string.IsNullOrWhiteSpace(originalText)
                        ? TrimForMessage(originalText)
                        : ReasonPhrases.GetReasonPhrase(status) ?? "Error",
            details = details ?? (!string.IsNullOrWhiteSpace(originalText) ? originalText : null)
          };

          context.Response.Body = originalBody;
          context.Response.StatusCode = StatusCodes.Status200OK;
          context.Response.ContentType = "application/json";
          await JsonSerializer.SerializeAsync(context.Response.Body, payload, new JsonSerializerOptions
          {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
          });
        }
        else
        {
          // pass-through on success
          context.Response.Body = originalBody;
          if (memStream.Length > 0)
          {
            memStream.Position = 0;
            await memStream.CopyToAsync(context.Response.Body);
          }
        }
      }
      finally
      {
        // ensure body is restored in case of exception
        context.Response.Body = originalBody;
      }
    }

    private static object? TryParseJson(string text)
    {
      if (string.IsNullOrWhiteSpace(text)) return null;
      try
      {
        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.Clone();
      }
      catch
      {
        return null;
      }
    }

    private static string TrimForMessage(string input)
    {
      // simple single-line message extraction
      var msg = input.Trim();
      var newline = msg.IndexOf('\n');
      if (newline > 0) msg = msg.Substring(0, newline).Trim();
      return msg;
    }
  }

  public static class Always200ResponseExtensions
  {
    public static IApplicationBuilder UseAlways200ResponseWrapper(this IApplicationBuilder app)
      => app.UseMiddleware<Always200ResponseMiddleware>();
  }
}

