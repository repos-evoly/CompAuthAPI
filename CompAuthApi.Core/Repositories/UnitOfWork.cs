using CompAuthApi.Core.Abstractions;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using System;
using System.Threading.Tasks;

namespace CompAuthApi.Core.Repositories
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly CompAuthApiDbContext _context;

        public IRepository<Role> Roles { get; }
        public IRepository<User> Users { get; }


        public IRepository<Settings> Settings { get; }

        public UnitOfWork(CompAuthApiDbContext context, IRepository<Role> rolesRepo, IRepository<User> usersRepo, IRepository<Settings> settingsRepo)
        {
            _context = context;
            Roles = rolesRepo;
            Users = usersRepo;

            Settings = settingsRepo;

        }

        public async Task SaveAsync()
        {
            await _context.SaveChangesAsync();
        }

        public void Dispose()
        {
            _context.Dispose();
        }
    }
}
