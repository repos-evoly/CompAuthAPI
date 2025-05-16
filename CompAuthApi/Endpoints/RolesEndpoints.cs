using CompAuthApi.Core.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using CompAuthApi.Core.Abstractions;
using AutoMapper;
using CompAuthApi.Data.Models;
using CompAuthApi.Abstractions;

namespace CompAuthApi.Endpoints
{
    public class RolesEndpoints : IEndpoints
    {
        public void RegisterEndpoints(WebApplication app)
        {
            var roles = app.MapGroup("/api/roles").RequireAuthorization("requireAuthUser");

            roles.MapGet("/", GetAll)
                .WithName("GetRoles")
                .Produces<IEnumerable<RoleDto>>(200);

            roles.MapGet("/{id:int}", GetById)
                .WithName("GetRoleById")
                .Produces<RoleDto>(200)
                .Produces(404);

            roles.MapPost("/", Create)
                .WithName("CreateRole")
                .Accepts<EditRoleDto>("application/json")
                .Produces<RoleDto>(201)
                .Produces(400);

            roles.MapPut("/{id:int}", Update)
                .WithName("UpdateRole")
                .Accepts<EditRoleDto>("application/json")
                .Produces<RoleDto>(200)
                .Produces(400);

            roles.MapDelete("/{id:int}", Delete)
                .WithName("DeleteRole")
                .Produces(204)
                .Produces(400);
        }

        public static async Task<IResult> GetAll([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper)
        {
            var roles = await unitOfWork.Roles.GetAll();
            return TypedResults.Ok(mapper.Map<IEnumerable<RoleDto>>(roles));
        }

        public static async Task<IResult> GetById([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper, int id)
        {
            var role = await unitOfWork.Roles.GetById(r => r.Id == id);
            return role != null ? TypedResults.Ok(mapper.Map<RoleDto>(role)) : TypedResults.NotFound("Role not found.");
        }

        [Authorize(Roles = "Admin")]
        public static async Task<IResult> Create([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper, [FromBody] EditRoleDto roleDto)
        {
            if (roleDto == null) return TypedResults.BadRequest("Invalid role data.");

            var role = mapper.Map<Role>(roleDto);
            await unitOfWork.Roles.Create(role);
            await unitOfWork.SaveAsync();

            return TypedResults.Created($"/api/roles/{role.Id}", mapper.Map<RoleDto>(role));
        }

        [Authorize(Roles = "Admin")]
        public static async Task<IResult> Update([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper, int id, [FromBody] EditRoleDto roleDto)
        {
            var role = await unitOfWork.Roles.GetById(r => r.Id == id);
            if (role == null) return TypedResults.BadRequest("Invalid role data.");

            mapper.Map(roleDto, role);
            unitOfWork.Roles.Update(role);
            await unitOfWork.SaveAsync();

            return TypedResults.Ok(mapper.Map<RoleDto>(role));
        }

        [Authorize(Roles = "Admin")]
        public static async Task<IResult> Delete([FromServices] IUnitOfWork unitOfWork, int id)
        {
            var role = await unitOfWork.Roles.GetById(r => r.Id == id);
            if (role == null) return TypedResults.NotFound("Role not found.");

            unitOfWork.Roles.Delete(role);
            await unitOfWork.SaveAsync();

            return TypedResults.NoContent();
        }
    }
}
