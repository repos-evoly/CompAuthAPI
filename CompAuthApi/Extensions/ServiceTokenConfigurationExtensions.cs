namespace CompAuthApi.Extensions;

public static class ServiceTokenConfigurationExtensions
{
    private static readonly IReadOnlyDictionary<string, string> Aliases =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["SERVICE_TOKEN_ISSUER"] = "ServiceTokens:Issuer",
            ["SERVICE_TOKEN_AUDIENCE"] = "ServiceTokens:Audience",
            ["SERVICE_TOKEN_ENVIRONMENT"] = "ServiceTokens:Environment",
            ["SERVICE_TOKEN_REQUIRED_SCOPE"] = "ServiceTokens:RequiredScope",
            ["SERVICE_TOKEN_PRIVATE_KEY"] = "ServiceTokens:PrivateKeyPem",
            ["SERVICE_TOKEN_PUBLIC_KEY"] = "ServiceTokens:PublicKeyPem",
            ["SERVICE_TOKEN_LIFETIME_SECONDS"] = "ServiceTokens:LifetimeSeconds",
            ["MOBILE_AUTH_CHALLENGE_LIFETIME_SECONDS"] =
                "ServiceTokens:ChallengeLifetimeSeconds",
            ["DEVICE_SECURITY_ENABLED"] = "DeviceSecurity:Enabled",
            ["DEVICE_AUTO_APPROVE_WITH_ACTIVATION_CODE"] = "DeviceSecurity:AutoApproveWithActivationCode",
            ["DEVICE_REQUIRE_ATTESTATION"] = "DeviceSecurity:RequireAttestation",
            ["DEVICE_ENROLLMENT_CHALLENGE_LIFETIME_SECONDS"] = "DeviceSecurity:EnrollmentChallengeLifetimeSeconds",
            ["DEVICE_LOGIN_CHALLENGE_LIFETIME_SECONDS"] = "DeviceSecurity:LoginChallengeLifetimeSeconds",
            ["DEVICE_ACTIVATION_CODE_LIFETIME_MINUTES"] = "DeviceSecurity:ActivationCodeLifetimeMinutes",
            ["DEVICE_SESSION_LIFETIME_MINUTES"] = "DeviceSecurity:DeviceSessionLifetimeMinutes"
        };

    public static IConfigurationBuilder AddServiceTokenEnvironmentAliases(
        this IConfigurationBuilder configuration)
    {
        var values = Aliases
            .Select(alias => new
            {
                Key = alias.Value,
                Value = Environment.GetEnvironmentVariable(alias.Key)
            })
            .Where(item => !string.IsNullOrWhiteSpace(item.Value))
            .ToDictionary(
                item => item.Key,
                item => item.Value,
                StringComparer.OrdinalIgnoreCase);

        var clientId = Environment.GetEnvironmentVariable("SERVICE_AUTH_CLIENT_ID");
        var clientSecret = Environment.GetEnvironmentVariable("SERVICE_AUTH_CLIENT_SECRET");
        var allowedScopes = Environment.GetEnvironmentVariable("SERVICE_AUTH_ALLOWED_SCOPES");
        if (!string.IsNullOrWhiteSpace(clientId))
        {
            if (!string.IsNullOrWhiteSpace(clientSecret))
            {
                values[$"ServiceTokens:Clients:{clientId}:Secret"] = clientSecret;
            }

            if (!string.IsNullOrWhiteSpace(allowedScopes))
            {
                values[$"ServiceTokens:Clients:{clientId}:AllowedScopes"] = allowedScopes;
            }
        }

        return configuration.AddInMemoryCollection(values!);
    }
}
