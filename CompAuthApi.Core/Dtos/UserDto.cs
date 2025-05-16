namespace CompAuthApi.Core.Dtos
{

  public class UserDto
  {
    public int Id { get; set; }
    public string? FullNameAR { get; set; }
    public string? FullNameLT { get; set; }
    public string? Email { get; set; }
    public bool Active { get; set; }
    public string? Role { get; set; }
    public bool IsTwoFactorEnabled { get; set; }
    public string? PasswordResetToken { get; set; }
    public DateTimeOffset? LastLogin { get; set; }
    public DateTimeOffset? LastLogout { get; set; }
  }

  public class CreateUserDto
  {
    public required string FullNameAR { get; set; }
    public required string FullNameLT { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
    public bool Active { get; set; }
    public int RoleId { get; set; }
  }
  public class EditUserDto
  {
    public required string FullNameAR { get; set; }
    public required string FullNameLT { get; set; }
    public required string Email { get; set; }
    public bool Active { get; set; }
    public int RoleId { get; set; }
  }


}