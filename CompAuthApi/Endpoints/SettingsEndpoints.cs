using CompAuthApi.Core.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using CompAuthApi.Core.Abstractions;
using AutoMapper;
using CompAuthApi.Data.Models;
using CompAuthApi.Abstractions;

namespace CompAuthApi.Endpoints
{
    public class SettingsEndpoints : IEndpoints
    {
        public void RegisterEndpoints(WebApplication app)
        {
            var settings = app.MapGroup("/api/settings").RequireAuthorization("requireAuthUser");

            settings.MapGet("/", Get)
                .WithName("GetSettings")
                .Produces<SettingsDto>(200);

            settings.MapPut("/", Update)
                .WithName("UpdateSettings")
                .Accepts<EditSettingsDto>("application/json")
                .Produces<SettingsDto>(200)
                .Produces(400);
        }

        public static async Task<IResult> Get([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper)
        {
            var settings = await unitOfWork.Settings.GetById(s => s.Id == 1);
            if (settings == null) return TypedResults.NotFound("Settings not found.");

            return TypedResults.Ok(mapper.Map<SettingsDto>(settings));
        }

        [Authorize(Roles = "Admin")]
        public static async Task<IResult> Update([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper, [FromBody] EditSettingsDto settingsDto)
        {
            var settings = await unitOfWork.Settings.GetById(s => s.Id == 1);
            if (settings == null) return TypedResults.NotFound("Settings not found.");

            mapper.Map(settingsDto, settings);
            unitOfWork.Settings.Update(settings);
            await unitOfWork.SaveAsync();

            return TypedResults.Ok(mapper.Map<SettingsDto>(settings));
        }
    }
}
