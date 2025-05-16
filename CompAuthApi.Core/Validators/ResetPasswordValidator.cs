using CompAuthApi.Core.Dtos;
using FluentValidation;

namespace CompAuthApi.Validators
{
  public class ResetPasswordValidator : AbstractValidator<ResetPasswordDto>
  {
    public ResetPasswordValidator()
    {
      RuleFor(u => u.PasswordToken).NotNull().NotEmpty().MinimumLength(6);
      RuleFor(u => u.Password).NotNull().NotEmpty().MinimumLength(3);

      // Validate that ConfirmPassword is identical to Password
      RuleFor(u => u.ConfirmPassword)
          .Equal(u => u.Password)
          .WithMessage("ConfirmPassword must match the Password field")
          .NotNull()
          .NotEmpty();
    }
  }
}
