using CompAuthApi.Core.Extensions;
using FluentValidation;
using Microsoft.AspNetCore.Http;

namespace CompAuthApi.Core.Filters;

public class ValidationFilter<T> : IEndpointFilter where T : class
{
    private readonly IValidator<T> _validator;

    public ValidationFilter(IValidator<T> validator)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator)); // Ensure validator is not null
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var arg = context.Arguments.SingleOrDefault(a => a is T) as T;

        if (arg == null)
            return Results.BadRequest("The argument is invalid.");

        var result = await _validator.ValidateAsync(arg);
        if (!result.IsValid)
        {
            var errors = result.Errors.GetErrors();
            return Results.Problem(errors);
        }

        return await next(context);
    }
}
