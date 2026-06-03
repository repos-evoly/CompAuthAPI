namespace CompAuthApi.Core.Dtos
{
    public class UpdateUserSecurityDto
    {
        public bool IsLocked { get; set; }
        public int LoginAttemptCount { get; set; }
    }
}