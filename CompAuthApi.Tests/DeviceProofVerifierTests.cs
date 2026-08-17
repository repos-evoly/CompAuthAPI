using System.Security.Cryptography;
using System.Text;
using CompAuthApi.Core.Devices;

namespace CompAuthApi.Tests;

public sealed class DeviceProofVerifierTests
{
    [Fact]
    public void Verify_AcceptsValidRsaProofAndRejectsModifiedInstallation()
    {
        using var key = RSA.Create(2048);
        var publicKey = key.ExportSubjectPublicKeyInfoPem();
        var challengeId = Guid.NewGuid();
        const string nonce = "one-time-nonce";
        const string installationId = "installation-01";
        var payload = Encoding.UTF8.GetBytes(DeviceProofVerifier.BuildPayload(
            DeviceSecurityService.LoginPurpose,
            challengeId,
            nonce,
            installationId));
        var signature = Convert.ToBase64String(key.SignData(
            payload,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));

        Assert.True(DeviceProofVerifier.Verify(
            DeviceProofVerifier.RsaSha256,
            publicKey,
            DeviceSecurityService.LoginPurpose,
            challengeId,
            nonce,
            installationId,
            signature));
        Assert.False(DeviceProofVerifier.Verify(
            DeviceProofVerifier.RsaSha256,
            publicKey,
            DeviceSecurityService.LoginPurpose,
            challengeId,
            nonce,
            "installation-02",
            signature));
    }

    [Fact]
    public void Verify_AcceptsValidP256ProofAndRejectsWrongPurpose()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportSubjectPublicKeyInfoPem();
        var challengeId = Guid.NewGuid();
        const string nonce = "one-time-nonce";
        const string installationId = "ios-installation";
        var payload = Encoding.UTF8.GetBytes(DeviceProofVerifier.BuildPayload(
            DeviceSecurityService.EnrollmentPurpose,
            challengeId,
            nonce,
            installationId));
        var signature = Convert.ToBase64String(key.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        Assert.True(DeviceProofVerifier.Verify(
            DeviceProofVerifier.EcdsaP256Sha256,
            publicKey,
            DeviceSecurityService.EnrollmentPurpose,
            challengeId,
            nonce,
            installationId,
            signature));
        Assert.False(DeviceProofVerifier.Verify(
            DeviceProofVerifier.EcdsaP256Sha256,
            publicKey,
            DeviceSecurityService.LoginPurpose,
            challengeId,
            nonce,
            installationId,
            signature));
    }

    [Fact]
    public void ValidateAndFingerprintPublicKey_RejectsWeakRsaKey()
    {
        using var key = RSA.Create(1024);

        Assert.Throws<CryptographicException>(() =>
            DeviceProofVerifier.ValidateAndFingerprintPublicKey(
                DeviceProofVerifier.RsaSha256,
                key.ExportSubjectPublicKeyInfoPem()));
    }
}
