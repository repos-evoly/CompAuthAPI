using System.Security.Cryptography;
using System.Text;

namespace CompAuthApi.Core.Devices;

public static class DeviceProofVerifier
{
    public const string RsaSha256 = "rsa-sha256";
    public const string EcdsaP256Sha256 = "ecdsa-p256-sha256";

    public static string ValidateAndFingerprintPublicKey(
        string algorithm,
        string publicKeyPem)
    {
        var keyBytes = ImportPublicKey(algorithm, publicKeyPem, out var key);
        key.Dispose();
        return Convert.ToHexString(SHA256.HashData(keyBytes));
    }

    public static bool Verify(
        string algorithm,
        string publicKeyPem,
        string purpose,
        Guid challengeId,
        string nonce,
        string installationId,
        string signature)
    {
        byte[] signatureBytes;
        try
        {
            signatureBytes = DecodeBase64(signature);
        }
        catch (FormatException)
        {
            return false;
        }

        var payload = Encoding.UTF8.GetBytes(BuildPayload(
            purpose,
            challengeId,
            nonce,
            installationId));
        try
        {
            ImportPublicKey(algorithm, publicKeyPem, out var key);
            using (key)
            {
                return key switch
                {
                    RSA rsa => rsa.VerifyData(
                        payload,
                        signatureBytes,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1),
                    ECDsa ecdsa =>
                        ecdsa.VerifyData(
                            payload,
                            signatureBytes,
                            HashAlgorithmName.SHA256,
                            DSASignatureFormat.IeeeP1363FixedFieldConcatenation) ||
                        ecdsa.VerifyData(
                            payload,
                            signatureBytes,
                            HashAlgorithmName.SHA256,
                            DSASignatureFormat.Rfc3279DerSequence),
                    _ => false
                };
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static string BuildPayload(
        string purpose,
        Guid challengeId,
        string nonce,
        string installationId) =>
        string.Join(
            '\n',
            "company-gateway-device-proof-v1",
            purpose,
            challengeId.ToString("N"),
            nonce,
            installationId);

    private static byte[] ImportPublicKey(
        string algorithm,
        string publicKeyPem,
        out AsymmetricAlgorithm key)
    {
        if (string.Equals(algorithm, RsaSha256, StringComparison.OrdinalIgnoreCase))
        {
            var rsa = RSA.Create();
            try
            {
                rsa.ImportFromPem(publicKeyPem);
                if (rsa.KeySize < 2048)
                {
                    throw new CryptographicException("RSA device keys must be at least 2048 bits.");
                }

                key = rsa;
                return rsa.ExportSubjectPublicKeyInfo();
            }
            catch
            {
                rsa.Dispose();
                throw;
            }
        }

        if (string.Equals(algorithm, EcdsaP256Sha256, StringComparison.OrdinalIgnoreCase))
        {
            var ecdsa = ECDsa.Create();
            try
            {
                ecdsa.ImportFromPem(publicKeyPem);
                if (ecdsa.KeySize != 256)
                {
                    throw new CryptographicException("ECDSA device keys must use P-256.");
                }

                key = ecdsa;
                return ecdsa.ExportSubjectPublicKeyInfo();
            }
            catch
            {
                ecdsa.Dispose();
                throw;
            }
        }

        throw new CryptographicException("Unsupported device-key algorithm.");
    }

    private static byte[] DecodeBase64(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized += (normalized.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            _ => string.Empty
        };
        return Convert.FromBase64String(normalized);
    }
}
