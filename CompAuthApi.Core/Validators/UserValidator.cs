using CompAuthApi.Core.Dtos;
using FluentValidation;

namespace CompAuthApi.Validators;

public class UserValidator : AbstractValidator<EditUserDto>
{
  public UserValidator()
  {
    RuleFor(u => u.FullNameAR).NotNull().NotEmpty().MinimumLength(3);
    RuleFor(u => u.FullNameLT).NotNull().NotEmpty().MinimumLength(3);
    RuleFor(u => u.Email).EmailAddress().NotNull().NotEmpty();
  }
}