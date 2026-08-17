using CompAuthApi.Abstractions;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Dtos;
using Microsoft.AspNetCore.RateLimiting;

namespace CompAuthApi.Endpoints;

public sealed class ServiceAuthEndpoints : IEndpoints
{
    public void RegisterEndpoints(WebApplication app)
    {
        app.MapPost("/api/service-auth/token", IssueToken)
            .AllowAnonymous()
            .RequireRateLimiting("service-auth-token")
            .WithTags("Service Authentication")
            .Produces<ServiceTokenResponseDto>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    private static IResult IssueToken(
        ServiceTokenRequestDto request,
        IServiceTokenService serviceTokenService,
        ILogger<ServiceAuthEndpoints> logger)
    {
        try
        {
            var token = serviceTokenService.Issue(request);
            logger.LogInformation(
                "Issued a Mobile BFF service token for client {ClientId}.",
                request.ClientId);
            return Results.Ok(new ServiceTokenResponseDto(
                token.AccessToken,
                "Bearer",
                token.ExpiresIn,
                token.Scope));
        }
        catch (InvalidServiceClientException)
        {
            logger.LogWarning(
                "Rejected a service-token request because client authentication failed.");
            return Problem(
                StatusCodes.Status401Unauthorized,
                "invalid_client",
                "Service-client authentication failed.");
        }
        catch (InvalidServiceTokenRequestException exception)
        {
            return Problem(
                StatusCodes.Status400BadRequest,
                exception.Code,
                exception.Message);
        }
        catch (ServiceTokenConfigurationException)
        {
            logger.LogError("Service-token issuance is not configured.");
            return Problem(
                StatusCodes.Status503ServiceUnavailable,
                "service_auth_not_configured",
                "Service authentication is unavailable.");
        }
    }

    private static IResult Problem(int status, string code, string detail) =>
        Results.Problem(
            statusCode: status,
            title: "Service authentication failed",
            detail: detail,
            extensions: new Dictionary<string, object?> { ["code"] = code });
}
