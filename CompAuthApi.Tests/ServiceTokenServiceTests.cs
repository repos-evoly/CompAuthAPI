using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Dtos;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace CompAuthApi.Tests;

public sealed class ServiceTokenServiceTests : IDisposable
{
    private const string ClientId = "company-gateway-mobile-bff-uat";
    private readonly RSA _rsa = RSA.Create(2048);

    [Fact]
    public void Issue_ProducesAValidServiceIdentity()
    {
        var service = CreateService();

        var issued = service.Issue(ValidRequest());
        var principal = service.ValidateServiceToken(issued.AccessToken);

        Assert.Equal("service", principal.FindFirst("token_type")?.Value);
        Assert.Equal(ClientId, principal.FindFirst("client_id")?.Value);
        Assert.Equal("uat", principal.FindFirst("environment")?.Value);
        Assert.Contains("company-gateway.mobile", principal.FindFirst("scope")?.Value);
        Assert.Equal(300, issued.ExpiresIn);
    }

    [Fact]
    public void Issue_RejectsInvalidClientSecret()
    {
        var service = CreateService();
        var request = ValidRequest();
        request.ClientSecret = "wrong-secret";

        Assert.Throws<InvalidServiceClientException>(() => service.Issue(request));
    }

    [Theory]
    [InlineData("wrong-audience", "company-gateway.mobile", "invalid_audience")]
    [InlineData("company-gateway-internal-apis-uat", "admin", "invalid_scope")]
    public void Issue_RejectsUnapprovedAudienceOrScope(
        string audience,
        string scope,
        string expectedCode)
    {
        var service = CreateService();
        var request = ValidRequest();
        request.Audience = audience;
        request.Scope = scope;

        var exception = Assert.Throws<InvalidServiceTokenRequestException>(
            () => service.Issue(request));

        Assert.Equal(expectedCode, exception.Code);
    }

    [Fact]
    public void ValidateServiceToken_RejectsATokenFromAnotherEnvironment()
    {
        var uatService = CreateService();
        var token = uatService.Issue(ValidRequest()).AccessToken;
        var liveService = CreateService(environment: "live");

        Assert.Throws<SecurityTokenValidationException>(
            () => liveService.ValidateServiceToken(token));
    }

    [Fact]
    public void ValidateServiceToken_RejectsWrongTokenType()
    {
        var service = CreateService();
        var token = CreateCustomToken(
            issuer: "company-gateway-service-auth",
            audience: "company-gateway-internal-apis-uat",
            expires: DateTime.UtcNow.AddMinutes(5),
            claims:
            [
                new Claim("token_type", "user"),
                new Claim("client_id", ClientId),
                new Claim("scope", "company-gateway.mobile"),
                new Claim("environment", "uat")
            ]);

        Assert.Throws<SecurityTokenValidationException>(
            () => service.ValidateServiceToken(token));
    }

    [Theory]
    [InlineData("wrong-issuer", "company-gateway-internal-apis-uat")]
    [InlineData("company-gateway-service-auth", "wrong-audience")]
    public void ValidateServiceToken_RejectsWrongIssuerOrAudience(
        string issuer,
        string audience)
    {
        var service = CreateService();
        var token = CreateCustomToken(
            issuer,
            audience,
            DateTime.UtcNow.AddMinutes(5),
            ValidServiceClaims());

        Assert.ThrowsAny<SecurityTokenException>(
            () => service.ValidateServiceToken(token));
    }

    [Fact]
    public void ValidateServiceToken_RejectsInvalidSignature()
    {
        using var otherKey = RSA.Create(2048);
        var service = CreateService();
        var token = CreateCustomToken(
            "company-gateway-service-auth",
            "company-gateway-internal-apis-uat",
            DateTime.UtcNow.AddMinutes(5),
            ValidServiceClaims(),
            otherKey);

        Assert.ThrowsAny<SecurityTokenException>(
            () => service.ValidateServiceToken(token));
    }

    [Theory]
    [InlineData("company-gateway-mobile-bff-unknown", "company-gateway.mobile")]
    [InlineData(ClientId, "unapproved-scope")]
    public void ValidateServiceToken_RejectsUnapprovedClientOrMissingScope(
        string clientId,
        string scope)
    {
        var service = CreateService();
        var token = CreateCustomToken(
            "company-gateway-service-auth",
            "company-gateway-internal-apis-uat",
            DateTime.UtcNow.AddMinutes(5),
            ValidServiceClaims(clientId, scope));

        Assert.Throws<SecurityTokenValidationException>(
            () => service.ValidateServiceToken(token));
    }

    [Fact]
    public void ValidateServiceToken_RejectsExpiredToken()
    {
        var service = CreateService();
        var token = CreateCustomToken(
            issuer: "company-gateway-service-auth",
            audience: "company-gateway-internal-apis-uat",
            expires: DateTime.UtcNow.AddMinutes(-2),
            claims:
            [
                new Claim("token_type", "service"),
                new Claim("client_id", ClientId),
                new Claim("scope", "company-gateway.mobile"),
                new Claim("environment", "uat")
            ]);

        Assert.Throws<SecurityTokenExpiredException>(
            () => service.ValidateServiceToken(token));
    }

    [Fact]
    public void MobileChallenge_IsBoundToLoginDeviceAndPurpose()
    {
        var service = CreateService();
        var challenge = service.Issue("admin@company.ly", "device-01", "verify_2fa");

        Assert.True(service.Validate(
            challenge.Token,
            "admin@company.ly",
            "device-01",
            "verify_2fa"));
        Assert.False(service.Validate(
            challenge.Token,
            "other@company.ly",
            "device-01",
            "verify_2fa"));
        Assert.False(service.Validate(
            challenge.Token,
            "admin@company.ly",
            "other-device",
            "verify_2fa"));
        Assert.False(service.Validate(
            challenge.Token,
            "admin@company.ly",
            "device-01",
            "enable_2fa"));
    }

    private ServiceTokenService CreateService(string environment = "uat")
    {
        var options = new ServiceTokenOptions
        {
            Issuer = "company-gateway-service-auth",
            Audience = "company-gateway-internal-apis-uat",
            Environment = environment,
            RequiredScope = "company-gateway.mobile",
            PrivateKeyPem = _rsa.ExportRSAPrivateKeyPem(),
            PublicKeyPem = _rsa.ExportSubjectPublicKeyInfoPem(),
            LifetimeSeconds = 300,
            ChallengeLifetimeSeconds = 300,
            Clients = new Dictionary<string, ServiceClientOptions>
            {
                [ClientId] = new()
                {
                    Secret = "test-secret-with-sufficient-entropy",
                    AllowedScopes = "company-gateway.mobile"
                }
            }
        };

        return new ServiceTokenService(
            new StaticOptionsMonitor<ServiceTokenOptions>(options),
            TimeProvider.System);
    }

    private static ServiceTokenRequestDto ValidRequest() => new()
    {
        ClientId = ClientId,
        ClientSecret = "test-secret-with-sufficient-entropy",
        Scope = "company-gateway.mobile",
        Audience = "company-gateway-internal-apis-uat"
    };

    private string CreateCustomToken(
        string issuer,
        string audience,
        DateTime expires,
        IEnumerable<Claim> claims,
        RSA? signingKey = null)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = issuer,
            Audience = audience,
            NotBefore = DateTime.UtcNow.AddMinutes(-10),
            Expires = expires,
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(signingKey ?? _rsa),
                SecurityAlgorithms.RsaSha256)
        };
        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    private static Claim[] ValidServiceClaims(
        string clientId = ClientId,
        string scope = "company-gateway.mobile") =>
    [
        new Claim("token_type", "service"),
        new Claim("client_id", clientId),
        new Claim("scope", scope),
        new Claim("environment", "uat")
    ];

    public void Dispose() => _rsa.Dispose();

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
