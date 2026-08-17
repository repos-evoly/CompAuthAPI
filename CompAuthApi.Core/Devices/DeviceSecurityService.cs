using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CompAuthApi.Core.Devices;

public interface IDeviceSecurityService
{
    bool IsEnabled { get; }
    Task<DeviceEnrollmentChallengeResponse> CreateEnrollmentChallengeAsync(
        DeviceEnrollmentChallengeRequest request,
        CancellationToken cancellationToken);
    Task<DeviceEnrollmentResponse> CompleteEnrollmentAsync(
        DeviceEnrollmentRequest request,
        CancellationToken cancellationToken);
    Task<DeviceLoginChallengeResponse> CreateLoginChallengeAsync(
        DeviceLoginChallengeRequest request,
        CancellationToken cancellationToken);
    Task<DeviceStatusResponse> GetStatusAsync(
        string installationId,
        CancellationToken cancellationToken);
    Task<DeviceLoginAuthorization> AuthorizeLoginAsync(
        MobileDeviceLoginProofRequest request,
        CancellationToken cancellationToken);
    Task<JsonElement> CompleteLoginAsync(
        DeviceLoginAuthorization authorization,
        string login,
        JsonElement response,
        CancellationToken cancellationToken);
    Task<DeviceLoginAuthorization> AuthorizeTwoFactorAsync(
        string login,
        string installationId,
        string challengeToken,
        CancellationToken cancellationToken);
    Task<JsonElement> CompleteTwoFactorAsync(
        DeviceLoginAuthorization authorization,
        string login,
        string challengeToken,
        JsonElement response,
        CancellationToken cancellationToken);
    Task<ValidatedDeviceSession> ValidateSessionAsync(
        string token,
        int? expectedAuthUserId,
        CancellationToken cancellationToken);
    Task RevokeSessionAsync(Guid sessionId, CancellationToken cancellationToken);
    Task TouchSessionAsync(Guid sessionId, CancellationToken cancellationToken);
}

public sealed class DeviceSecurityService : IDeviceSecurityService
{
    public const string EnrollmentPurpose = "enrollment";
    public const string LoginPurpose = "login";

    private readonly CompAuthApiDbContext _db;
    private readonly IDeviceAttestationValidator _attestationValidator;
    private readonly IOptionsMonitor<DeviceSecurityOptions> _options;
    private readonly TimeProvider _timeProvider;

    public DeviceSecurityService(
        CompAuthApiDbContext db,
        IDeviceAttestationValidator attestationValidator,
        IOptionsMonitor<DeviceSecurityOptions> options,
        TimeProvider timeProvider)
    {
        _db = db;
        _attestationValidator = attestationValidator;
        _options = options;
        _timeProvider = timeProvider;
    }

    public bool IsEnabled => _options.CurrentValue.Enabled;

    public async Task<DeviceEnrollmentChallengeResponse> CreateEnrollmentChallengeAsync(
        DeviceEnrollmentChallengeRequest request,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var now = _timeProvider.GetUtcNow();
        var activationHash = HashSecret(request.ActivationCode);
        var activation = await _db.DeviceActivationCodes
            .FirstOrDefaultAsync(code => code.CodeHash == activationHash, cancellationToken);
        if (activation is null || activation.ExpiresAt <= now ||
            activation.UsedAt is not null || activation.UsedByDeviceId is not null)
        {
            throw new InvalidActivationCodeException();
        }

        if (await _db.MobileDevices.AnyAsync(
                device => device.InstallationId == request.InstallationId,
                cancellationToken))
        {
            throw new DeviceEnrollmentConflictException();
        }

        string fingerprint;
        try
        {
            fingerprint = DeviceProofVerifier.ValidateAndFingerprintPublicKey(
                request.KeyAlgorithm,
                request.PublicKeyPem);
        }
        catch (CryptographicException)
        {
            throw new InvalidDevicePublicKeyException();
        }

        var attestation = await _attestationValidator.ValidateAsync(
            request.Platform,
            request.InstallationId,
            request.AttestationProvider,
            request.AttestationToken,
            cancellationToken);

        var device = new MobileDevice
        {
            Id = Guid.NewGuid(),
            InstallationId = request.InstallationId,
            TargetAuthUserId = activation.TargetAuthUserId,
            LoginHash = activation.LoginHash,
            CompanyCode = activation.CompanyCode,
            Platform = request.Platform.ToLowerInvariant(),
            AppVersion = NormalizeOptional(request.AppVersion),
            KeyAlgorithm = request.KeyAlgorithm.ToLowerInvariant(),
            PublicKeyPem = request.PublicKeyPem.Trim(),
            PublicKeyFingerprint = fingerprint,
            AttestationProvider = attestation.Provider,
            AttestationStatus = attestation.Status,
            Status = DeviceRegistrationStatus.Pending,
            CreatedAt = now,
            UpdatedAt = now
        };
        var challenge = CreateChallenge(
            device.Id,
            activation.Id,
            EnrollmentPurpose,
            now,
            _options.CurrentValue.EnrollmentChallengeLifetimeSeconds);

        activation.UsedByDeviceId = device.Id;
        _db.MobileDevices.Add(device);
        _db.DeviceChallenges.Add(challenge);
        await _db.SaveChangesAsync(cancellationToken);

        return new DeviceEnrollmentChallengeResponse(
            challenge.Id,
            challenge.Nonce,
            challenge.ExpiresAt,
            EnrollmentPurpose,
            device.Id);
    }

    public async Task<DeviceEnrollmentResponse> CompleteEnrollmentAsync(
        DeviceEnrollmentRequest request,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var now = _timeProvider.GetUtcNow();
        var challenge = await _db.DeviceChallenges
            .AsNoTracking()
            .Include(item => item.MobileDevice)
            .Include(item => item.ActivationCode)
            .FirstOrDefaultAsync(item => item.Id == request.ChallengeId, cancellationToken);
        if (challenge is null || challenge.Purpose != EnrollmentPurpose ||
            challenge.UsedAt is not null || challenge.ExpiresAt <= now ||
            challenge.ActivationCode is null ||
            challenge.ActivationCode.UsedAt is not null ||
            challenge.ActivationCode.UsedByDeviceId != challenge.MobileDeviceId)
        {
            throw new InvalidDeviceChallengeException();
        }

        if (!DeviceProofVerifier.Verify(
                challenge.MobileDevice.KeyAlgorithm,
                challenge.MobileDevice.PublicKeyPem,
                EnrollmentPurpose,
                challenge.Id,
                challenge.Nonce,
                challenge.MobileDevice.InstallationId,
                request.Signature))
        {
            throw new InvalidDeviceProofException();
        }

        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken);
        var consumedChallenge = await _db.DeviceChallenges
            .Where(item => item.Id == challenge.Id && item.UsedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(item => item.UsedAt, now),
                cancellationToken);
        var consumedCode = await _db.DeviceActivationCodes
            .Where(code =>
                code.Id == challenge.ActivationCodeId &&
                code.UsedAt == null &&
                code.UsedByDeviceId == challenge.MobileDeviceId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(code => code.UsedAt, now),
                cancellationToken);
        if (consumedChallenge != 1 || consumedCode != 1)
        {
            throw new InvalidDeviceChallengeException();
        }

        var device = await _db.MobileDevices
            .FirstAsync(item => item.Id == challenge.MobileDeviceId, cancellationToken);
        device.ProofVerifiedAt = now;
        device.UpdatedAt = now;
        if (_options.CurrentValue.AutoApproveWithActivationCode)
        {
            device.Status = DeviceRegistrationStatus.Approved;
            device.ApprovedAt = now;
            device.ApprovedByAuthUserId = challenge.ActivationCode.CreatedByAuthUserId;
        }

        await _db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new DeviceEnrollmentResponse(
            device.Id,
            device.InstallationId,
            device.Status.ToString().ToLowerInvariant(),
            device.ProofVerifiedAt.Value);
    }

    public async Task<DeviceLoginChallengeResponse> CreateLoginChallengeAsync(
        DeviceLoginChallengeRequest request,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var device = await _db.MobileDevices
            .AsNoTracking()
            .FirstOrDefaultAsync(
                item => item.InstallationId == request.InstallationId,
                cancellationToken);
        if (device is null || device.Status != DeviceRegistrationStatus.Approved)
        {
            throw new DeviceNotApprovedException();
        }

        var now = _timeProvider.GetUtcNow();
        var challenge = CreateChallenge(
            device.Id,
            null,
            LoginPurpose,
            now,
            _options.CurrentValue.LoginChallengeLifetimeSeconds);
        _db.DeviceChallenges.Add(challenge);
        await _db.SaveChangesAsync(cancellationToken);

        return new DeviceLoginChallengeResponse(
            challenge.Id,
            challenge.Nonce,
            challenge.ExpiresAt,
            LoginPurpose);
    }

    public async Task<DeviceStatusResponse> GetStatusAsync(
        string installationId,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var device = await _db.MobileDevices
            .AsNoTracking()
            .FirstOrDefaultAsync(
                item => item.InstallationId == installationId,
                cancellationToken);
        return device is null
            ? new DeviceStatusResponse(false, "not_registered", null, null)
            : new DeviceStatusResponse(
                true,
                device.Status.ToString().ToLowerInvariant(),
                device.ApprovedAt,
                device.RevokedAt);
    }

    public async Task<DeviceLoginAuthorization> AuthorizeLoginAsync(
        MobileDeviceLoginProofRequest request,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        if (request.DeviceChallengeId is null ||
            string.IsNullOrWhiteSpace(request.DeviceSignature))
        {
            throw new DeviceProofRequiredException();
        }

        var now = _timeProvider.GetUtcNow();
        var challenge = await _db.DeviceChallenges
            .AsNoTracking()
            .Include(item => item.MobileDevice)
            .FirstOrDefaultAsync(
                item => item.Id == request.DeviceChallengeId.Value,
                cancellationToken);
        if (challenge is null || challenge.Purpose != LoginPurpose ||
            challenge.UsedAt is not null || challenge.ExpiresAt <= now ||
            challenge.MobileDevice.InstallationId != request.DeviceId ||
            challenge.MobileDevice.Status != DeviceRegistrationStatus.Approved ||
            challenge.MobileDevice.LoginHash != HashLogin(request.Login))
        {
            throw new InvalidDeviceChallengeException();
        }

        if (!DeviceProofVerifier.Verify(
                challenge.MobileDevice.KeyAlgorithm,
                challenge.MobileDevice.PublicKeyPem,
                LoginPurpose,
                challenge.Id,
                challenge.Nonce,
                challenge.MobileDevice.InstallationId,
                request.DeviceSignature))
        {
            throw new InvalidDeviceProofException();
        }

        var consumed = await _db.DeviceChallenges
            .Where(item => item.Id == challenge.Id && item.UsedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(item => item.UsedAt, now),
                cancellationToken);
        if (consumed != 1)
        {
            throw new InvalidDeviceChallengeException();
        }

        await _db.MobileDevices
            .Where(device => device.Id == challenge.MobileDeviceId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(device => device.LastSeenAt, now)
                    .SetProperty(device => device.UpdatedAt, now),
                cancellationToken);

        return new DeviceLoginAuthorization(
            challenge.MobileDevice.Id,
            challenge.MobileDevice.InstallationId,
            challenge.MobileDevice.TargetAuthUserId);
    }

    public async Task<JsonElement> CompleteLoginAsync(
        DeviceLoginAuthorization authorization,
        string login,
        JsonElement response,
        CancellationToken cancellationToken)
    {
        if (TryReadString(response, "challengeToken", out var challengeToken))
        {
            var expiresIn = TryReadInt(response, "challengeExpiresIn") ?? 300;
            _db.DeviceLoginGrants.Add(new DeviceLoginGrant
            {
                Id = Guid.NewGuid(),
                MobileDeviceId = authorization.DeviceId,
                ChallengeTokenHash = HashSecret(challengeToken),
                LoginHash = HashLogin(login),
                CreatedAt = _timeProvider.GetUtcNow(),
                ExpiresAt = _timeProvider.GetUtcNow().AddSeconds(Math.Clamp(expiresIn, 30, 600))
            });
            await _db.SaveChangesAsync(cancellationToken);
            return response;
        }

        return await CreateDeviceSessionFromAuthResponseAsync(
            authorization,
            response,
            null,
            cancellationToken);
    }

    public async Task<DeviceLoginAuthorization> AuthorizeTwoFactorAsync(
        string login,
        string installationId,
        string challengeToken,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var now = _timeProvider.GetUtcNow();
        var tokenHash = HashSecret(challengeToken);
        var loginHash = HashLogin(login);
        var grant = await _db.DeviceLoginGrants
            .AsNoTracking()
            .Include(item => item.MobileDevice)
            .FirstOrDefaultAsync(item =>
                item.ChallengeTokenHash == tokenHash &&
                item.LoginHash == loginHash &&
                item.UsedAt == null &&
                item.ExpiresAt > now &&
                item.MobileDevice.InstallationId == installationId &&
                item.MobileDevice.Status == DeviceRegistrationStatus.Approved,
                cancellationToken);
        if (grant is null)
        {
            throw new InvalidDeviceLoginGrantException();
        }

        return new DeviceLoginAuthorization(
            grant.MobileDeviceId,
            grant.MobileDevice.InstallationId,
            grant.MobileDevice.TargetAuthUserId);
    }

    public async Task<JsonElement> CompleteTwoFactorAsync(
        DeviceLoginAuthorization authorization,
        string login,
        string challengeToken,
        JsonElement response,
        CancellationToken cancellationToken) =>
        await CreateDeviceSessionFromAuthResponseAsync(
            authorization,
            response,
            HashSecret(challengeToken),
            cancellationToken);

    public async Task<ValidatedDeviceSession> ValidateSessionAsync(
        string token,
        int? expectedAuthUserId,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var now = _timeProvider.GetUtcNow();
        var tokenHash = HashSecret(token);
        var session = await _db.DeviceSessions
            .AsNoTracking()
            .Include(item => item.MobileDevice)
            .FirstOrDefaultAsync(item =>
                item.TokenHash == tokenHash &&
                item.RevokedAt == null &&
                item.ExpiresAt > now &&
                item.MobileDevice.Status == DeviceRegistrationStatus.Approved,
                cancellationToken);
        if (session is null ||
            (expectedAuthUserId.HasValue && session.AuthUserId != expectedAuthUserId.Value))
        {
            throw new InvalidDeviceSessionException();
        }

        return new ValidatedDeviceSession(
            session.Id,
            session.MobileDeviceId,
            session.AuthUserId,
            session.CompAuthSessionId,
            session.ExpiresAt);
    }

    public Task RevokeSessionAsync(Guid sessionId, CancellationToken cancellationToken) =>
        _db.DeviceSessions
            .Where(session => session.Id == sessionId && session.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    session => session.RevokedAt,
                    _timeProvider.GetUtcNow()),
                cancellationToken);

    public Task TouchSessionAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        return _db.DeviceSessions
            .Where(session => session.Id == sessionId && session.LastSeenAt < now.AddMinutes(-1))
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(session => session.LastSeenAt, now),
                cancellationToken);
    }

    private async Task<JsonElement> CreateDeviceSessionFromAuthResponseAsync(
        DeviceLoginAuthorization authorization,
        JsonElement response,
        string? loginGrantHash,
        CancellationToken cancellationToken)
    {
        if (!TryReadString(response, "accessToken", out var accessToken) ||
            !TryReadString(response, "sessionId", out var compAuthSessionId) ||
            !DeviceUserAccessToken.TryGetUserId(accessToken, out var authUserId))
        {
            return response;
        }

        if (authUserId != authorization.TargetAuthUserId)
        {
            throw new DeviceUserMismatchException();
        }

        var now = _timeProvider.GetUtcNow();
        var configuredExpiry = now.AddMinutes(
            Math.Clamp(_options.CurrentValue.DeviceSessionLifetimeMinutes, 5, 1440));
        var compAuthExpiry = TryReadDate(response, "sessionExpiresAt");
        var expiresAt = compAuthExpiry.HasValue && compAuthExpiry.Value < configuredExpiry
            ? compAuthExpiry.Value
            : configuredExpiry;
        var rawToken = RandomToken(32);

        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken);
        if (loginGrantHash is not null)
        {
            var consumed = await _db.DeviceLoginGrants
                .Where(grant =>
                    grant.ChallengeTokenHash == loginGrantHash &&
                    grant.MobileDeviceId == authorization.DeviceId &&
                    grant.UsedAt == null &&
                    grant.ExpiresAt > now)
                .ExecuteUpdateAsync(
                    setters => setters.SetProperty(grant => grant.UsedAt, now),
                    cancellationToken);
            if (consumed != 1)
            {
                throw new InvalidDeviceLoginGrantException();
            }
        }

        await _db.DeviceSessions
            .Where(session =>
                session.MobileDeviceId == authorization.DeviceId &&
                session.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(session => session.RevokedAt, now),
                cancellationToken);

        var session = new DeviceSession
        {
            Id = Guid.NewGuid(),
            MobileDeviceId = authorization.DeviceId,
            AuthUserId = authUserId,
            CompAuthSessionId = compAuthSessionId,
            TokenHash = HashSecret(rawToken),
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = expiresAt
        };
        _db.DeviceSessions.Add(session);
        await _db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        var result = JsonNode.Parse(response.GetRawText())!.AsObject();
        result["deviceSessionToken"] = rawToken;
        result["deviceSessionExpiresAt"] = expiresAt;
        return JsonSerializer.SerializeToElement(result);
    }

    private DeviceChallenge CreateChallenge(
        Guid deviceId,
        Guid? activationCodeId,
        string purpose,
        DateTimeOffset now,
        int configuredLifetimeSeconds) =>
        new()
        {
            Id = Guid.NewGuid(),
            MobileDeviceId = deviceId,
            ActivationCodeId = activationCodeId,
            Purpose = purpose,
            Nonce = RandomToken(32),
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(Math.Clamp(configuredLifetimeSeconds, 30, 600))
        };

    private void EnsureEnabled()
    {
        if (!IsEnabled)
        {
            throw new DeviceSecurityDisabledException();
        }

    }

    public static string HashLogin(string value) =>
        Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(value.Trim().ToUpperInvariant())));

    public static string HashSecret(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string RandomToken(int bytes)
    {
        var value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes));
        return value.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string? NormalizeOptional(string? value)
    {
        var normalized = value?.Trim();
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }

    private static bool TryReadString(
        JsonElement response,
        string property,
        out string value)
    {
        value = string.Empty;
        return response.ValueKind == JsonValueKind.Object &&
               response.TryGetProperty(property, out var element) &&
               element.ValueKind == JsonValueKind.String &&
               !string.IsNullOrWhiteSpace(value = element.GetString() ?? string.Empty);
    }

    private static int? TryReadInt(JsonElement response, string property) =>
        response.ValueKind == JsonValueKind.Object &&
        response.TryGetProperty(property, out var element) &&
        element.TryGetInt32(out var value)
            ? value
            : null;

    private static DateTimeOffset? TryReadDate(JsonElement response, string property) =>
        response.ValueKind == JsonValueKind.Object &&
        response.TryGetProperty(property, out var element) &&
        element.TryGetDateTimeOffset(out var value)
            ? value
            : null;
}

public sealed record DeviceEnrollmentChallengeRequest(
    string ActivationCode,
    string InstallationId,
    string Platform,
    string? AppVersion,
    string KeyAlgorithm,
    string PublicKeyPem,
    string? AttestationProvider,
    string? AttestationToken);

public sealed record DeviceEnrollmentChallengeResponse(
    Guid ChallengeId,
    string Nonce,
    DateTimeOffset ExpiresAt,
    string Purpose,
    Guid DeviceId);

public sealed record DeviceEnrollmentRequest(Guid ChallengeId, string Signature);

public sealed record DeviceEnrollmentResponse(
    Guid DeviceId,
    string InstallationId,
    string Status,
    DateTimeOffset ProofVerifiedAt);

public sealed record DeviceLoginChallengeRequest(string InstallationId);

public sealed record DeviceLoginChallengeResponse(
    Guid ChallengeId,
    string Nonce,
    DateTimeOffset ExpiresAt,
    string Purpose);

public sealed record MobileDeviceLoginProofRequest(
    string Login,
    string DeviceId,
    Guid? DeviceChallengeId,
    string? DeviceSignature);

public sealed record DeviceStatusResponse(
    bool Registered,
    string Status,
    DateTimeOffset? ApprovedAt,
    DateTimeOffset? RevokedAt);

public sealed record DeviceLoginAuthorization(
    Guid DeviceId,
    string InstallationId,
    int TargetAuthUserId);

public sealed record ValidatedDeviceSession(
    Guid SessionId,
    Guid DeviceId,
    int AuthUserId,
    string CompAuthSessionId,
    DateTimeOffset ExpiresAt);

public sealed class DeviceSecurityDisabledException : Exception;
public sealed class InvalidActivationCodeException : Exception;
public sealed class DeviceEnrollmentConflictException : Exception;
public sealed class InvalidDevicePublicKeyException : Exception;
public sealed class InvalidDeviceChallengeException : Exception;
public sealed class InvalidDeviceProofException : Exception;
public sealed class DeviceNotApprovedException : Exception;
public sealed class DeviceProofRequiredException : Exception;
public sealed class InvalidDeviceLoginGrantException : Exception;
public sealed class InvalidDeviceSessionException : Exception;
public sealed class DeviceUserMismatchException : Exception;


internal static class DeviceUserAccessToken
{
    public static bool TryGetUserId(string bearerToken, out int userId)
    {
        userId = 0;
        var parts = bearerToken.Split('.');
        if (parts.Length != 3) return false;
        try
        {
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + ((4 - payload.Length % 4) % 4), '=');
            using var json = JsonDocument.Parse(Convert.FromBase64String(payload));
            foreach (var claimName in new[] { "nameid", "sub", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" })
            {
                if (json.RootElement.TryGetProperty(claimName, out var claim) &&
                    int.TryParse(claim.ToString(), out userId) && userId > 0) return true;
            }
        }
        catch (FormatException) { }
        catch (JsonException) { }
        return false;
    }
}
