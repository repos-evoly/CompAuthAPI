using System.ComponentModel.DataAnnotations;

namespace CompAuthApi.Core.Dtos
{
    public class RoleDto
    {
        public int Id { get; set; }
        public string? TitleLt { get; set; }

        public string? TitleAR { get; set; }

    }
}
