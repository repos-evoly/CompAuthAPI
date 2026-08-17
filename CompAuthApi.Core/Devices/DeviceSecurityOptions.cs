namespace CompAuthApi.Core.Devices;

public sealed class DeviceSecurityOptions
{
    public const string SectionName = "DeviceSecurity";

    public bool Enabled { get; init; }
    public bool AutoApproveWithActivationCode { get; init; } = true;
    public bool RequireAttestation { get; init; }
    public int EnrollmentChallengeLifetimeSeconds { get; init; } = 300;
    public int LoginChallengeLifetimeSeconds { get; init; } = 60;
    public int ActivationCodeLifetimeMinutes { get; init; } = 30;
    public int DeviceSessionLifetimeMinutes { get; init; } = 180;
}
