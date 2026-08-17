using Microsoft.Extensions.Options;

namespace CompAuthApi.Core.Devices;

public interface IDeviceAttestationValidator
{
    Task<DeviceAttestationResult> ValidateAsync(
        string platform,
        string installationId,
        string? provider,
        string? attestationToken,
        CancellationToken cancellationToken);
}

public sealed class DeviceAttestationValidator(
    IOptionsMonitor<DeviceSecurityOptions> options) : IDeviceAttestationValidator
{
    public Task<DeviceAttestationResult> ValidateAsync(
        string platform,
        string installationId,
        string? provider,
        string? attestationToken,
        CancellationToken cancellationToken)
    {
        if (options.CurrentValue.RequireAttestation)
        {
            throw new DeviceAttestationUnavailableException();
        }

        return Task.FromResult(new DeviceAttestationResult(
            provider?.Trim(),
            string.IsNullOrWhiteSpace(attestationToken)
                ? "not_required"
                : "not_verified"));
    }
}

public sealed record DeviceAttestationResult(string? Provider, string Status);
public sealed class DeviceAttestationUnavailableException : Exception;
