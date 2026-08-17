using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CompAuthApi.Core.Devices;

public interface IMobilePushTokenService
{
    Task<MobilePushTokenRegistrationResponse> RegisterAsync(
        int authUserId,
        MobilePushTokenRegistrationRequest request,
        CancellationToken cancellationToken);
    Task<MobilePushTokenRemovalResponse> RemoveAsync(
        int authUserId,
        Guid deviceId,
        CancellationToken cancellationToken);
    Task<MobilePushTokenStatusResponse> GetStatusAsync(
        int authUserId,
        Guid deviceId,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<MobilePushTargetResponse>> ResolveTargetsAsync(
        IReadOnlyCollection<int> authUserIds,
        CancellationToken cancellationToken);
    Task<MobilePushTokenInvalidationResponse> InvalidateAsync(
        IReadOnlyCollection<Guid> deviceIds,
        CancellationToken cancellationToken);
}

public sealed class MobilePushTokenService(
    CompAuthApiDbContext db,
    IOptionsMonitor<DeviceSecurityOptions> options,
    TimeProvider timeProvider) : IMobilePushTokenService
{
    private const int MaximumTargetUsers = 500;

    public async Task<MobilePushTokenRegistrationResponse> RegisterAsync(
        int authUserId,
        MobilePushTokenRegistrationRequest request,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var token = NormalizeAndValidateToken(request.Token);
        var platform = NormalizePlatform(request.Platform);
        var appVersion = NormalizeAppVersion(request.AppVersion);
        var device = await FindApprovedDeviceAsync(
            authUserId,
            request.DeviceId,
            cancellationToken);
        if (!string.Equals(device.Platform, platform, StringComparison.OrdinalIgnoreCase))
        {
            throw new PushTokenPlatformMismatchException();
        }

        var now = timeProvider.GetUtcNow();
        var tokenHash = DeviceSecurityService.HashSecret(token);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Firebase can rotate and reassign a registration token. Keep exactly one
        // approved-device owner for each token so an old installation cannot remain targeted.
        await db.MobilePushTokens
            .Where(item =>
                item.TokenHash == tokenHash &&
                item.MobileDeviceId != device.Id)
            .ExecuteDeleteAsync(cancellationToken);

        var registration = await db.MobilePushTokens
            .FirstOrDefaultAsync(
                item => item.MobileDeviceId == device.Id,
                cancellationToken);
        if (registration is null)
        {
            registration = new MobilePushToken
            {
                MobileDeviceId = device.Id,
                AuthUserId = authUserId,
                Token = token,
                TokenHash = tokenHash,
                Platform = platform,
                AppVersion = appVersion,
                CreatedAt = now,
                UpdatedAt = now
            };
            db.MobilePushTokens.Add(registration);
        }
        else
        {
            registration.AuthUserId = authUserId;
            registration.Token = token;
            registration.TokenHash = tokenHash;
            registration.Platform = platform;
            registration.AppVersion = appVersion;
            registration.UpdatedAt = now;
        }

        device.AppVersion = appVersion ?? device.AppVersion;
        device.UpdatedAt = now;
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new MobilePushTokenRegistrationResponse(
            device.Id,
            true,
            platform,
            appVersion,
            registration.UpdatedAt);
    }

    public async Task<MobilePushTokenRemovalResponse> RemoveAsync(
        int authUserId,
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        _ = await FindApprovedDeviceAsync(authUserId, deviceId, cancellationToken);
        var removed = await db.MobilePushTokens
            .Where(item =>
                item.MobileDeviceId == deviceId &&
                item.AuthUserId == authUserId)
            .ExecuteDeleteAsync(cancellationToken);
        return new MobilePushTokenRemovalResponse(deviceId, removed > 0);
    }

    public async Task<MobilePushTokenStatusResponse> GetStatusAsync(
        int authUserId,
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        _ = await FindApprovedDeviceAsync(authUserId, deviceId, cancellationToken);
        var registration = await db.MobilePushTokens
            .AsNoTracking()
            .Where(item =>
                item.MobileDeviceId == deviceId &&
                item.AuthUserId == authUserId)
            .Select(item => new
            {
                item.Platform,
                item.AppVersion,
                item.UpdatedAt
            })
            .FirstOrDefaultAsync(cancellationToken);
        return registration is null
            ? new MobilePushTokenStatusResponse(deviceId, false, null, null, null)
            : new MobilePushTokenStatusResponse(
                deviceId,
                true,
                registration.Platform,
                registration.AppVersion,
                registration.UpdatedAt);
    }

    public async Task<IReadOnlyList<MobilePushTargetResponse>> ResolveTargetsAsync(
        IReadOnlyCollection<int> authUserIds,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var requestedUserIds = authUserIds
            .Where(id => id > 0)
            .Distinct()
            .ToArray();
        if (requestedUserIds.Length == 0 ||
            requestedUserIds.Length > MaximumTargetUsers ||
            requestedUserIds.Length != authUserIds.Distinct().Count())
        {
            throw new InvalidPushTargetRequestException();
        }

        return await (
                from registration in db.MobilePushTokens.AsNoTracking()
                join device in db.MobileDevices.AsNoTracking()
                    on registration.MobileDeviceId equals device.Id
                join user in db.Users.AsNoTracking()
                    on registration.AuthUserId equals user.Id
                where requestedUserIds.Contains(registration.AuthUserId) &&
                      device.TargetAuthUserId == registration.AuthUserId &&
                      device.Status == DeviceRegistrationStatus.Approved &&
                      user.Active
                select new MobilePushTargetResponse(
                    registration.AuthUserId,
                    registration.MobileDeviceId,
                    registration.Token,
                    registration.Platform))
            .ToArrayAsync(cancellationToken);
    }

    public async Task<MobilePushTokenInvalidationResponse> InvalidateAsync(
        IReadOnlyCollection<Guid> deviceIds,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var requestedDeviceIds = deviceIds
            .Where(id => id != Guid.Empty)
            .Distinct()
            .ToArray();
        if (requestedDeviceIds.Length == 0 ||
            requestedDeviceIds.Length > MaximumTargetUsers ||
            requestedDeviceIds.Length != deviceIds.Distinct().Count())
        {
            throw new InvalidPushTargetRequestException();
        }

        var removed = await db.MobilePushTokens
            .Where(token => requestedDeviceIds.Contains(token.MobileDeviceId))
            .ExecuteDeleteAsync(cancellationToken);
        return new MobilePushTokenInvalidationResponse(removed);
    }

    private async Task<MobileDevice> FindApprovedDeviceAsync(
        int authUserId,
        Guid deviceId,
        CancellationToken cancellationToken) =>
        await db.MobileDevices.FirstOrDefaultAsync(
            device =>
                device.Id == deviceId &&
                device.TargetAuthUserId == authUserId &&
                device.Status == DeviceRegistrationStatus.Approved,
            cancellationToken) ?? throw new PushDeviceNotApprovedException();

    public static string NormalizeAndValidateToken(string? value)
    {
        var token = value?.Trim() ?? string.Empty;
        if (token.Length is < 20 or > 4096 ||
            token.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw new InvalidPushTokenException();
        }

        return token;
    }

    public static string NormalizePlatform(string? value)
    {
        var platform = value?.Trim().ToLowerInvariant();
        return platform is "android" or "ios"
            ? platform
            : throw new InvalidPushTokenException();
    }

    private static string? NormalizeAppVersion(string? value)
    {
        var appVersion = value?.Trim();
        if (appVersion?.Length > 32)
        {
            throw new InvalidPushTokenException();
        }

        return string.IsNullOrWhiteSpace(appVersion) ? null : appVersion;
    }

    private void EnsureEnabled()
    {
        if (!options.CurrentValue.Enabled)
        {
            throw new DeviceSecurityDisabledException();
        }
    }
}

public sealed record MobilePushTokenRegistrationRequest(
    Guid DeviceId,
    string Token,
    string Platform,
    string? AppVersion);

public sealed record MobilePushTokenRegistrationResponse(
    Guid DeviceId,
    bool Registered,
    string Platform,
    string? AppVersion,
    DateTimeOffset UpdatedAt);

public sealed record MobilePushTokenRemovalResponse(Guid DeviceId, bool Removed);

public sealed record MobilePushTokenStatusResponse(
    Guid DeviceId,
    bool Registered,
    string? Platform,
    string? AppVersion,
    DateTimeOffset? UpdatedAt);

public sealed record MobilePushTargetResponse(
    int AuthUserId,
    Guid DeviceId,
    string Token,
    string Platform);

public sealed record MobilePushTokenInvalidationResponse(int Removed);

public sealed class InvalidPushTokenException : Exception;
public sealed class PushTokenPlatformMismatchException : Exception;
public sealed class PushDeviceNotApprovedException : Exception;
public sealed class InvalidPushTargetRequestException : Exception;
