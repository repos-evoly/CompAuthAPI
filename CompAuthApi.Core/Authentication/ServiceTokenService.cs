using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CompAuthApi.Core.Dtos;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace CompAuthApi.Core.Authentication;

public interface IServiceTokenService
{
    ServiceTokenIssueResult Issue(ServiceTokenRequestDto request);
    ClaimsPrincipal ValidateServiceToken(string token);
}

public interface IMobileAuthChallengeService
{
    MobileAuthChallenge Issue(string login, string deviceId, string purpose);
    bool Validate(
        string token,
        string login,
        string deviceId,
        string expectedPurpose);
}

public sealed class ServiceTokenService : IServiceTokenService, IMobileAuthChallengeService
{
    private readonly IOptionsMonitor<ServiceTokenOptions> _options;
    private readonly TimeProvider _timeProvider;

    public ServiceTokenService(
        IOptionsMonitor<ServiceTokenOptions> options,
        TimeProvider timeProvider)
    {
        _options = options;
        _timeProvider = timeProvider;
    }

    public ServiceTokenIssueResult Issue(ServiceTokenRequestDto request)
    {
        var options = _options.CurrentValue;
        EnsureIssuerConfiguration(options, requirePrivateKey: true);

        if (string.IsNullOrWhiteSpace(request.ClientId) ||
            request.ClientId.Length > 128 ||
            string.IsNullOrWhiteSpace(request.ClientSecret) ||
            request.ClientSecret.Length > 512 ||
            string.IsNullOrWhiteSpace(request.Scope) ||
            request.Scope.Length > 512 ||
            string.IsNullOrWhiteSpace(request.Audience) ||
            request.Audience.Length > 256 ||
            !options.Clients.TryGetValue(request.ClientId, out var client) ||
            string.IsNullOrWhiteSpace(client.Secret) ||
            !SecretsMatch(client.Secret, request.ClientSecret))
        {
            throw new InvalidServiceClientException();
        }

        if (!string.Equals(request.Audience, options.Audience, StringComparison.Ordinal))
        {
            throw new InvalidServiceTokenRequestException(
                "invalid_audience",
                "The requested service-token audience is not allowed.");
        }

        var requestedScopes = ParseScopes(request.Scope);
        var allowedScopes = ParseScopes(client.AllowedScopes);
        if (requestedScopes.Count == 0 || !requestedScopes.IsSubsetOf(allowedScopes))
        {
            throw new InvalidServiceTokenRequestException(
                "invalid_scope",
                "One or more requested service scopes are not allowed.");
        }

        var lifetime = Math.Clamp(options.LifetimeSeconds, 60, 900);
        var now = _timeProvider.GetUtcNow();
        var expiresAt = now.AddSeconds(lifetime);
        var scope = string.Join(' ', requestedScopes.Order(StringComparer.Ordinal));
        var claims = new[]
        {
            new Claim("token_type", ServiceAuthenticationDefaults.ServiceTokenType),
            new Claim("client_id", request.ClientId),
            new Claim("scope", scope),
            new Claim("environment", options.Environment),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        };

        var token = CreateToken(
            options,
            options.Audience,
            claims,
            now,
            expiresAt);

        return new ServiceTokenIssueResult(token, lifetime, scope);
    }

    public ClaimsPrincipal ValidateServiceToken(string token)
    {
        var options = _options.CurrentValue;
        EnsureIssuerConfiguration(options, requirePrivateKey: false);

        var principal = ValidateToken(token, options, options.Audience);
        var clientId = principal.FindFirst("client_id")?.Value;
        var scopes = ParseScopes(principal.FindFirst("scope")?.Value);
        var approvedClient = !string.IsNullOrWhiteSpace(clientId) &&
                             options.Clients.TryGetValue(clientId, out var configuredClient)
            ? configuredClient
            : null;

        if (!string.Equals(
                principal.FindFirst("token_type")?.Value,
                ServiceAuthenticationDefaults.ServiceTokenType,
                StringComparison.Ordinal) ||
            approvedClient is null ||
            !string.Equals(
                principal.FindFirst("environment")?.Value,
                options.Environment,
                StringComparison.Ordinal) ||
            !scopes.Contains(options.RequiredScope) ||
            !scopes.IsSubsetOf(ParseScopes(approvedClient.AllowedScopes)))
        {
            throw new SecurityTokenValidationException(
                "The service token does not contain the required identity claims.");
        }

        return principal;
    }

    public MobileAuthChallenge Issue(string login, string deviceId, string purpose)
    {
        var options = _options.CurrentValue;
        EnsureIssuerConfiguration(options, requirePrivateKey: true);
        var lifetime = Math.Clamp(options.ChallengeLifetimeSeconds, 60, 600);
        var now = _timeProvider.GetUtcNow();
        var expiresAt = now.AddSeconds(lifetime);
        var claims = new[]
        {
            new Claim("token_type", ServiceAuthenticationDefaults.ChallengeTokenType),
            new Claim("login_hash", HashLogin(login)),
            new Claim("device_id", deviceId),
            new Claim("purpose", purpose),
            new Claim("environment", options.Environment),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        };

        return new MobileAuthChallenge(
            CreateToken(
                options,
                ServiceAuthenticationDefaults.ChallengeAudience,
                claims,
                now,
                expiresAt),
            lifetime);
    }

    public bool Validate(
        string token,
        string login,
        string deviceId,
        string expectedPurpose)
    {
        try
        {
            var options = _options.CurrentValue;
            EnsureIssuerConfiguration(options, requirePrivateKey: false);
            var principal = ValidateToken(
                token,
                options,
                ServiceAuthenticationDefaults.ChallengeAudience);

            return string.Equals(
                       principal.FindFirst("token_type")?.Value,
                       ServiceAuthenticationDefaults.ChallengeTokenType,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       principal.FindFirst("login_hash")?.Value,
                       HashLogin(login),
                       StringComparison.Ordinal) &&
                   string.Equals(
                       principal.FindFirst("device_id")?.Value,
                       deviceId,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       principal.FindFirst("purpose")?.Value,
                       expectedPurpose,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       principal.FindFirst("environment")?.Value,
                       options.Environment,
                       StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private ClaimsPrincipal ValidateToken(
        string token,
        ServiceTokenOptions options,
        string audience)
    {
        using var rsa = LoadRsa(options.PublicKeyPem);
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        return handler.ValidateToken(
            token,
            new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(rsa),
                RequireSignedTokens = true,
                ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
                ValidateIssuer = true,
                ValidIssuer = options.Issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            },
            out _);
    }

    private static string CreateToken(
        ServiceTokenOptions options,
        string audience,
        IEnumerable<Claim> claims,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        using var rsa = LoadRsa(options.PrivateKeyPem);
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = options.Issuer,
            Audience = audience,
            IssuedAt = issuedAt.UtcDateTime,
            NotBefore = issuedAt.UtcDateTime,
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(rsa),
                SecurityAlgorithms.RsaSha256)
        };

        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    private static RSA LoadRsa(string pem)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(NormalizePem(pem));
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw new ServiceTokenConfigurationException();
        }
    }

    private static void EnsureIssuerConfiguration(
        ServiceTokenOptions options,
        bool requirePrivateKey)
    {
        if (string.IsNullOrWhiteSpace(options.Issuer) ||
            string.IsNullOrWhiteSpace(options.Audience) ||
            string.IsNullOrWhiteSpace(options.Environment) ||
            string.IsNullOrWhiteSpace(options.RequiredScope) ||
            string.IsNullOrWhiteSpace(options.PublicKeyPem) ||
            (requirePrivateKey && string.IsNullOrWhiteSpace(options.PrivateKeyPem)))
        {
            throw new ServiceTokenConfigurationException();
        }
    }

    private static bool SecretsMatch(string expected, string provided)
    {
        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        var providedHash = SHA256.HashData(Encoding.UTF8.GetBytes(provided ?? string.Empty));
        return CryptographicOperations.FixedTimeEquals(expectedHash, providedHash);
    }

    private static HashSet<string> ParseScopes(string? value) =>
        (value ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.Ordinal);

    private static string HashLogin(string login) =>
        Base64UrlEncoder.Encode(SHA256.HashData(
            Encoding.UTF8.GetBytes(login.Trim().ToUpperInvariant())));

    private static string NormalizePem(string value) =>
        (value ?? string.Empty).Replace("\\n", "\n", StringComparison.Ordinal);
}

public sealed record ServiceTokenIssueResult(
    string AccessToken,
    int ExpiresIn,
    string Scope);

public sealed record MobileAuthChallenge(string Token, int ExpiresIn);

public sealed class InvalidServiceClientException : Exception;

public sealed class InvalidServiceTokenRequestException(
    string code,
    string message) : Exception(message)
{
    public string Code { get; } = code;
}

public sealed class ServiceTokenConfigurationException : Exception;
