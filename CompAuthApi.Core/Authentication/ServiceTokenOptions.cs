namespace CompAuthApi.Core.Authentication;

public sealed class ServiceTokenOptions
{
    public const string SectionName = "ServiceTokens";

    public string Issuer { get; init; } = string.Empty;
    public string Audience { get; init; } = string.Empty;
    public string Environment { get; init; } = string.Empty;
    public string RequiredScope { get; init; } = "company-gateway.mobile";
    public string PrivateKeyPem { get; init; } = string.Empty;
    public string PublicKeyPem { get; init; } = string.Empty;
    public int LifetimeSeconds { get; init; } = 300;
    public int ChallengeLifetimeSeconds { get; init; } = 300;
    public IDictionary<string, ServiceClientOptions> Clients { get; init; } =
        new Dictionary<string, ServiceClientOptions>(StringComparer.Ordinal);
}

public sealed class ServiceClientOptions
{
    public string Secret { get; init; } = string.Empty;
    public string AllowedScopes { get; init; } = "company-gateway.mobile";
}

public static class ServiceAuthenticationDefaults
{
    public const string Scheme = "MobileBffService";
    public const string HeaderName = "X-Service-Authorization";
    public const string RequireMobileBffServicePolicy = "RequireMobileBffService";
    public const string RequireCompanyUserAndMobileBffServicePolicy =
        "RequireCompanyUserAndMobileBffService";
    public const string ServiceTokenType = "service";
    public const string ChallengeTokenType = "mobile_auth_challenge";
    public const string ChallengeAudience = "company-gateway-mobile-auth";
}
