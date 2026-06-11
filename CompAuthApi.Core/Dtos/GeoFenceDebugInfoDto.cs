namespace CompAuthApi.Core.Dtos
{
    public class GeoFenceDebugInfoDto
    {
        public string? XForwardedFor { get; set; }
        public string? RemoteIpAddress { get; set; }
        public string? ClientIp { get; set; }
        public bool IsPrivateIp { get; set; }
        public string? ResolvedCountryCode { get; set; }
        public string? ResolvedCountryName { get; set; }
        public string? ResolutionStatus { get; set; }
    }
}
