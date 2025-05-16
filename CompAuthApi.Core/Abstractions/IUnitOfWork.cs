using CompAuthApi.Data.Models;

namespace CompAuthApi.Core.Abstractions
{
  public interface IUnitOfWork : IDisposable
  {
    IRepository<Role> Roles { get; }
    IRepository<User> Users { get; }
    IRepository<Settings> Settings { get; }

    Task SaveAsync();
  }
}