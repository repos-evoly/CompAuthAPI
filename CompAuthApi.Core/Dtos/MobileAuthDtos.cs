using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CompAuthApi.Core.Dtos;

public sealed class ServiceTokenRequestDto
{
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("client_secret")]
    public string ClientSecret { get; set; } = string.Empty;

    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;

    [JsonPropertyName("audience")]
    public string Audience { get; set; } = string.Empty;
}

public sealed record ServiceTokenResponseDto(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("scope")] string Scope);

public sealed class MobileLoginDto
{
    [Required, MaxLength(256)]
    public string Login { get; set; } = string.Empty;

    [Required, MaxLength(256)]
    public string Password { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string DeviceId { get; set; } = string.Empty;

    public Guid? DeviceChallengeId { get; set; }

    [MaxLength(2048)]
    public string? DeviceSignature { get; set; }
}

public class MobileTwoFactorSetupDto
{
    [Required, MaxLength(256)]
    public string Login { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string DeviceId { get; set; } = string.Empty;

    [Required, MaxLength(4096)]
    public string ChallengeToken { get; set; } = string.Empty;
}

public sealed class MobileVerifyTwoFactorDto : MobileTwoFactorSetupDto
{
    [Required, RegularExpression("^[0-9]{6}$")]
    public string Token { get; set; } = string.Empty;
}
