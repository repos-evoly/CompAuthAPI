using AutoMapper;
using CompAuthApi.Data.Models;
using CompAuthApi.Core.Dtos;

namespace CompAuthApi
{
  public class MappingConfig : Profile
  {
    public MappingConfig()
    {


      // Role Mappings
      CreateMap<Role, RoleDto>().ReverseMap();
      CreateMap<Role, EditRoleDto>().ReverseMap();

      // User Mappings
      CreateMap<User, UserDto>().ReverseMap();
      CreateMap<User, EditUserDto>().ReverseMap();

      CreateMap<Settings, SettingsDto>().ReverseMap();
      CreateMap<Settings, EditSettingsDto>().ReverseMap();
    }



  }
}