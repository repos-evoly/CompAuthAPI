namespace CompAuthApi.Core.Dtos
{
    public class AuthApiErrorResponseDto
    {
        public bool Success { get; set; } = false;
        public int Status { get; set; }
        public string Code { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string MessageEn { get; set; } = string.Empty;
        public string MessageAr { get; set; } = string.Empty;
        public object? Details { get; set; }
    }
}
