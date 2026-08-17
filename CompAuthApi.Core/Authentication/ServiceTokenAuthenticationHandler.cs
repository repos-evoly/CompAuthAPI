using System.Net.Http.Headers;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CompAuthApi.Core.Authentication;

public sealed class ServiceTokenAuthenticationHandler :
    AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IServiceTokenService _serviceTokenService;

    public ServiceTokenAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IServiceTokenService serviceTokenService)
        : base(options, logger, encoder)
    {
        _serviceTokenService = serviceTokenService;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var value = Request.Headers[ServiceAuthenticationDefaults.HeaderName]
            .FirstOrDefault();
        if (string.IsNullOrWhiteSpace(value))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!AuthenticationHeaderValue.TryParse(value, out var header) ||
            !string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(header.Parameter))
        {
            return Task.FromResult(AuthenticateResult.Fail(
                "The service authorization header is invalid."));
        }

        try
        {
            var principal = _serviceTokenService.ValidateServiceToken(header.Parameter);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(principal, Scheme.Name)));
        }
        catch (Exception exception)
        {
            Logger.LogWarning(
                "Service-token authentication failed with reason {FailureType}.",
                exception.GetType().Name);
            return Task.FromResult(AuthenticateResult.Fail("The service token is invalid."));
        }
    }
}
