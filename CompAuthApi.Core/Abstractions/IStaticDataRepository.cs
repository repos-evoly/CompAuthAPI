
using CompAuthApi.Core.Dtos;

namespace CompAuthApi.Core.Abstractions
{
  public interface IStaticDataRepository
  {
    public IEnumerable<RoleDto> GetRoles();
  }
}
