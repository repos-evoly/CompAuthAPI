using CompAuthApi.Core.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using CompAuthApi.Core.Abstractions;
using AutoMapper;
using CompAuthApi.Data.Models;
using CompAuthApi.Abstractions;
using CompAuthApi.Data.Context;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Endpoints
{
    public class UserEndpoints : IEndpoints
    {
        public void RegisterEndpoints(WebApplication app)
        {
            var users = app.MapGroup("/api/users").RequireAuthorization("requireAuthUser");

            users.MapGet("/", GetAll)
                .WithName("GetUsers")
                .Produces<IEnumerable<UserDto>>(200);

            users.MapGet("/{id:int}", GetById)
                .WithName("GetUserById")
                .Produces<UserDto>(200)
                .Produces(404);

            users.MapPost("/", Create)
                .WithName("CreateUser")
                .Accepts<EditUserDto>("application/json")
                .Produces<UserDto>(201)
                .Produces(400);

            users.MapPut("/{id:int}", Update)
                .WithName("UpdateUser")
                .Accepts<EditUserDto>("application/json")
                .Produces<UserDto>(200)
                .Produces(400);

            users.MapDelete("/{id:int}", Delete)
                .WithName("DeleteUser")
                .Produces(204)
                .Produces(400);

            users.MapPatch("/{id:int}/security", UpdateUserSecurity)
                .WithName("UpdateUserSecurity")
                .Accepts<UpdateUserSecurityDto>("application/json")
                .Produces(200)
                .Produces(404);
        }



        public static async Task<IResult> GetAll([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper)
        {
            var users = await unitOfWork.Users.GetAll(includes: new List<string> { "UserSecurity" });
            var userDtos = users.Select(user => new UserDto
            {
                Id = user.Id,
                Email = user.Email,
                Active = user.Active,
                Role = user.Role?.TitleLT,
                IsTwoFactorEnabled = user.UserSecurity?.IsTwoFactorEnabled ?? false,
                PasswordResetToken = user.UserSecurity?.PasswordResetToken,
                LastLogin = user.UserSecurity?.LastLogin,
                LastLogout = user.UserSecurity?.LastLogout,
            }).ToList();

            return TypedResults.Ok(userDtos);
        }

        public static async Task<IResult> GetById([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper, int id)
        {
            var user = await unitOfWork.Users.GetById(u => u.Id == id, includes: new List<string> { "UserSecurity" });
            if (user == null) return TypedResults.NotFound("User not found.");

            var userDto = new UserDto
            {
                Id = user.Id,
                Email = user.Email,
                Active = user.Active,
                Role = user.Role?.TitleLT,
                IsTwoFactorEnabled = user.UserSecurity?.IsTwoFactorEnabled ?? false,
                PasswordResetToken = user.UserSecurity?.PasswordResetToken,
                LastLogin = user.UserSecurity?.LastLogin,
                LastLogout = user.UserSecurity?.LastLogout,
            };

            return TypedResults.Ok(userDto);
        }

        [Authorize(Roles = "Admin")]
        public static async Task<IResult> Create([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper, [FromBody] CreateUserDto userDto)
        {
            if (userDto == null) return TypedResults.BadRequest("Invalid user data.");

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(userDto.Password);

            var user = new User
            {
                Email = userDto.Email,
                Password = hashedPassword,
                RoleId = userDto.RoleId,
                Active = userDto.Active,
                UserSecurity = new UserSecurity()
            };

            await unitOfWork.Users.Create(user);
            await unitOfWork.SaveAsync();

            return TypedResults.Created($"/api/users/{user.Id}", mapper.Map<UserDto>(user));
        }

        [Authorize(Roles = "Admin")]
        public static async Task<IResult> Update([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper, int id, [FromBody] EditUserDto userDto)
        {
            var user = await unitOfWork.Users.GetById(u => u.Id == id, includes: new List<string> { "UserSecurity" });
            if (user == null) return TypedResults.NotFound("User not found.");
            user.Email = userDto.Email;
            user.Active = userDto.Active;
            user.RoleId = userDto.RoleId;



            unitOfWork.Users.Update(user);
            await unitOfWork.SaveAsync();

            return TypedResults.Ok(mapper.Map<UserDto>(user));
        }

        [Authorize(Roles = "Admin")]
        public static async Task<IResult> Delete([FromServices] IUnitOfWork unitOfWork, int id)
        {
            var user = await unitOfWork.Users.GetById(u => u.Id == id);
            if (user == null) return TypedResults.NotFound("User not found.");

            unitOfWork.Users.Delete(user);
            await unitOfWork.SaveAsync();

            return TypedResults.NoContent();
        }


        public static async Task<IResult> UpdateUserSecurity([FromServices] CompAuthApiDbContext db, int id, [FromBody] UpdateUserSecurityDto dto)
        { 
            //selecting user with his security fields via id
            var user = await db.Users
                .Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.Id == id);
            
            //making sure the user exists
            if (user == null)
                return TypedResults.NotFound("User not found.");

            //making sure the user security options exist
            if (user.UserSecurity == null)
            {
                user.UserSecurity = new UserSecurity
                {
                    UserId = user.Id
                };
            }

            //updating the relivant user locked fields via DTO data
            user.UserSecurity.IsLocked = dto.IsLocked;
            user.UserSecurity.LoginAttemptCount = dto.LoginAttemptCount;

            // saving the changes to db and returning the updated fields
            await db.SaveChangesAsync();

            return TypedResults.Ok(new
            {
                Message = "User security updated successfully",
                UserId = user.Id,
                user.UserSecurity.IsLocked,
                user.UserSecurity.LoginAttemptCount
            });
        }

        // public static async Task<IResult> Unlock([FromServices] IUnitOfWork unitOfWork, [FromServices] IMapper mapper, int id)
        // {

        //     var user = await unitOfWork.Users.GetById(u => u.Id == id, includes: new List<string> { "UserSecurity" });
        //     if (user == null) return TypedResults.NotFound("User not found.");

        //     user.UserSecurity.IsLocked = false;
        //     user.UserSecurity.LoginAttemptCount = 0;
        //     Console.WriteLine(user.UserSecurity);
                
        //     unitOfWork.Users.Update(user);
        //     await unitOfWork.SaveAsync();
        //     return TypedResults.Ok(mapper.Map<UserDto>(user));
        // }
    }
}
