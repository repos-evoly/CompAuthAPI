namespace CompAuthApi.Core.Dtos
{
    public class GeoFenceEvaluationDto
    {
        public bool IsEnabled { get; set; }
        public bool IsAllowed { get; set; } = true;
        public string? FailureCode { get; set; }
        public string? FailureReason { get; set; }
        public string? CurrentCountryCode { get; set; }
        public string? CurrentCountryName { get; set; }
        public bool ShouldExposeDebugClientIp { get; set; }
        public GeoFenceDebugInfoDto? DebugClientIp { get; set; }
        public AuthApiErrorResponseDto? Error { get; set; }
    }
}
