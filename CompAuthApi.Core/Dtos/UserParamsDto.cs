namespace CompAuthApi.Core.Dtos
{
    public class EditUserParamsDto
    {
        public string? TitleAR { get; set; }
        public string? TitleLT { get; set; }
    }

    public class UserParamsDto : EditUserParamsDto
    {
        public int Id { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
    }
}