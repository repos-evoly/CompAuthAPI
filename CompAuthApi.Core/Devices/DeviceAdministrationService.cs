using System.Security.Cryptography;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CompAuthApi.Core.Devices;

public interface IDeviceAdministrationService
{
    Task<DeviceActivationCodeResponse> CreateActivationCodeAsync(
        int administratorAuthUserId,
        CreateDeviceActivationCodeRequest request,
        CancellationToken cancellationToken);
    Task<DevicePageResponse> GetDevicesAsync(
        string companyCode,
        int page,
        int limit,
        string? status,
        CancellationToken cancellationToken);
    Task<DeviceAdminResponse> ApproveAsync(
        int administratorAuthUserId,
        Guid deviceId,
        string companyCode,
        CancellationToken cancellationToken);
    Task<DeviceAdminResponse> RevokeAsync(
        int administratorAuthUserId,
        Guid deviceId,
        string companyCode,
        CancellationToken cancellationToken);
}

public sealed class DeviceAdministrationService : IDeviceAdministrationService
{
    private readonly CompAuthApiDbContext _db;
    private readonly IOptionsMonitor<DeviceSecurityOptions> _options;
    private readonly TimeProvider _timeProvider;

    public DeviceAdministrationService(
        CompAuthApiDbContext db,
        IOptionsMonitor<DeviceSecurityOptions> options,
        TimeProvider timeProvider)
    {
        _db = db;
        _options = options;
        _timeProvider = timeProvider;
    }

    public async Task<DeviceActivationCodeResponse> CreateActivationCodeAsync(
        int administratorAuthUserId,
        CreateDeviceActivationCodeRequest request,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var target = await _db.Users
            .AsNoTracking()
            .Where(user => user.Id == request.TargetAuthUserId)
            .Select(user => new { user.Username, user.Email, user.Active })
            .FirstOrDefaultAsync(cancellationToken);
        if (target is null || !target.Active ||
            (!MatchesLogin(request.Login, target.Username) &&
             !MatchesLogin(request.Login, target.Email)))
        {
            throw new DeviceTargetUserInvalidException();
        }

        var now = _timeProvider.GetUtcNow();
        var configuredMinutes = request.ExpiresInMinutes ??
                                _options.CurrentValue.ActivationCodeLifetimeMinutes;
        var rawCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var activation = new DeviceActivationCode
        {
            Id = Guid.NewGuid(),
            CodeHash = DeviceSecurityService.HashSecret(rawCode),
            TargetAuthUserId = request.TargetAuthUserId,
            LoginHash = DeviceSecurityService.HashLogin(request.Login),
            CreatedByAuthUserId = administratorAuthUserId,
            CompanyCode = request.CompanyCode,
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(Math.Clamp(configuredMinutes, 5, 1440))
        };
        _db.DeviceActivationCodes.Add(activation);
        await _db.SaveChangesAsync(cancellationToken);

        return new DeviceActivationCodeResponse(
            activation.Id,
            rawCode,
            activation.TargetAuthUserId,
            activation.ExpiresAt);
    }

    public async Task<DevicePageResponse> GetDevicesAsync(
        string companyCode,
        int page,
        int limit,
        string? status,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var query = _db.MobileDevices
            .AsNoTracking()
            .Where(device => device.CompanyCode == companyCode);
        if (!string.IsNullOrWhiteSpace(status))
        {
            if (!Enum.TryParse<DeviceRegistrationStatus>(status, true, out var parsedStatus))
            {
                throw new InvalidDeviceStatusException();
            }

            query = query.Where(device => device.Status == parsedStatus);
        }

        var total = await query.CountAsync(cancellationToken);
        var devices = await query
            .OrderByDescending(device => device.CreatedAt)
            .Skip((page - 1) * limit)
            .Take(limit)
            .ToArrayAsync(cancellationToken);
        return new DevicePageResponse(
            devices.Select(ToResponse).ToArray(),
            page,
            limit,
            total);
    }

    public async Task<DeviceAdminResponse> ApproveAsync(
        int administratorAuthUserId,
        Guid deviceId,
        string companyCode,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var device = await FindCompanyDeviceAsync(deviceId, companyCode, cancellationToken);
        if (device.Status != DeviceRegistrationStatus.Pending || device.ProofVerifiedAt is null)
        {
            throw new DeviceStateConflictException();
        }

        var now = _timeProvider.GetUtcNow();
        device.Status = DeviceRegistrationStatus.Approved;
        device.ApprovedAt = now;
        device.ApprovedByAuthUserId = administratorAuthUserId;
        device.UpdatedAt = now;
        await _db.SaveChangesAsync(cancellationToken);
        return ToResponse(device);
    }

    public async Task<DeviceAdminResponse> RevokeAsync(
        int administratorAuthUserId,
        Guid deviceId,
        string companyCode,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var device = await FindCompanyDeviceAsync(deviceId, companyCode, cancellationToken);
        if (device.Status == DeviceRegistrationStatus.Revoked)
        {
            throw new DeviceStateConflictException();
        }

        var now = _timeProvider.GetUtcNow();
        device.Status = DeviceRegistrationStatus.Revoked;
        device.RevokedAt = now;
        device.RevokedByAuthUserId = administratorAuthUserId;
        device.UpdatedAt = now;
        await _db.DeviceSessions
            .Where(session => session.MobileDeviceId == deviceId && session.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(session => session.RevokedAt, now),
                cancellationToken);
        await _db.MobilePushTokens
            .Where(token => token.MobileDeviceId == deviceId)
            .ExecuteDeleteAsync(cancellationToken);
        await _db.SaveChangesAsync(cancellationToken);
        return ToResponse(device);
    }

    private async Task<MobileDevice> FindCompanyDeviceAsync(
        Guid deviceId,
        string companyCode,
        CancellationToken cancellationToken) =>
        await _db.MobileDevices.FirstOrDefaultAsync(
            device => device.Id == deviceId && device.CompanyCode == companyCode,
            cancellationToken) ?? throw new DeviceNotFoundException();

    private static bool MatchesLogin(string supplied, string? expected) =>
        !string.IsNullOrWhiteSpace(expected) &&
        string.Equals(supplied.Trim(), expected.Trim(), StringComparison.OrdinalIgnoreCase);

    private static DeviceAdminResponse ToResponse(MobileDevice device) =>
        new(
            device.Id,
            device.InstallationId,
            device.TargetAuthUserId,
            device.Platform,
            device.AppVersion,
            device.Status.ToString().ToLowerInvariant(),
            device.PublicKeyFingerprint,
            device.AttestationStatus,
            device.CreatedAt,
            device.ProofVerifiedAt,
            device.ApprovedAt,
            device.RevokedAt,
            device.LastSeenAt);

    private void EnsureEnabled()
    {
        if (!_options.CurrentValue.Enabled)
        {
            throw new DeviceSecurityDisabledException();
        }
    }
}

public sealed record CreateDeviceActivationCodeRequest(
    int TargetAuthUserId,
    string Login,
    string CompanyCode,
    int? ExpiresInMinutes = null);

public sealed record DeviceActivationCodeResponse(
    Guid ActivationId,
    string ActivationCode,
    int TargetAuthUserId,
    DateTimeOffset ExpiresAt);

public sealed record DeviceAdminResponse(
    Guid DeviceId,
    string InstallationId,
    int TargetAuthUserId,
    string Platform,
    string? AppVersion,
    string Status,
    string PublicKeyFingerprint,
    string? AttestationStatus,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ProofVerifiedAt,
    DateTimeOffset? ApprovedAt,
    DateTimeOffset? RevokedAt,
    DateTimeOffset? LastSeenAt);

public sealed record DevicePageResponse(
    IReadOnlyList<DeviceAdminResponse> Data,
    int Page,
    int Limit,
    int TotalRecords);

public sealed class DeviceTargetUserInvalidException : Exception;
public sealed class InvalidDeviceStatusException : Exception;
public sealed class DeviceNotFoundException : Exception;
public sealed class DeviceStateConflictException : Exception;
