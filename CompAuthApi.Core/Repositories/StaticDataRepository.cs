using AutoMapper;
using CompAuthApi.Core.Dtos;
using CompAuthApi.Data.Context;
using CompAuthApi.Core.Abstractions;

namespace CompAuthApi.Core.Repositories
{
  public class StaticDataRepository : IStaticDataRepository
  {
    private readonly CompAuthApiDbContext _db;
    private readonly IMapper _mapper;

    public StaticDataRepository(CompAuthApiDbContext db, IMapper mapper)
    {
      _db = db;
      _mapper = mapper;
    }

    public IEnumerable<RoleDto> GetRoles()
    {
      return _mapper.Map<IEnumerable<RoleDto>>(_db.Roles.ToList());
    }

  }
}