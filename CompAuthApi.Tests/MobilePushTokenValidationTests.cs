using CompAuthApi.Core.Devices;

namespace CompAuthApi.Tests;

public sealed class MobilePushTokenValidationTests
{
    [Fact]
    public void NormalizeAndValidateToken_AcceptsFirebaseRegistrationToken()
    {
        var token = "firebase-registration-token_1234567890:example";

        Assert.Equal(token, MobilePushTokenService.NormalizeAndValidateToken($"  {token}  "));
    }

    [Theory]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("firebase token containing whitespace")]
    public void NormalizeAndValidateToken_RejectsInvalidValues(string token)
    {
        Assert.Throws<InvalidPushTokenException>(
            () => MobilePushTokenService.NormalizeAndValidateToken(token));
    }

    [Theory]
    [InlineData("ANDROID", "android")]
    [InlineData(" ios ", "ios")]
    public void NormalizePlatform_NormalizesSupportedPlatforms(
        string supplied,
        string expected)
    {
        Assert.Equal(expected, MobilePushTokenService.NormalizePlatform(supplied));
    }

    [Theory]
    [InlineData("web")]
    [InlineData("")]
    public void NormalizePlatform_RejectsUnsupportedPlatforms(string platform)
    {
        Assert.Throws<InvalidPushTokenException>(
            () => MobilePushTokenService.NormalizePlatform(platform));
    }
}
