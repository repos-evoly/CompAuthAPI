using System.Linq.Expressions;
using CompAuthApi.Core.Abstractions;
using CompAuthApi.Data.Context;
using Microsoft.EntityFrameworkCore;

namespace CompAuthApi.Core.Repositories
{
  public class Repository<T> : IRepository<T> where T : class
  {
    private readonly CompAuthApiDbContext _ctx;
    private readonly DbSet<T> _db;

    public Repository(CompAuthApiDbContext ctx)
    {
      _ctx = ctx ?? throw new ArgumentNullException(nameof(ctx));
      _db = _ctx.Set<T>();
    }

    public async Task<T?> GetById(Expression<Func<T, bool>> expression, List<string>? includes = null)
    {
      IQueryable<T> query = _db;
      if (includes != null)
      {
        foreach (var includeProp in includes)
        {
          query = query.Include(includeProp);
        }
      }

      return await query.AsNoTracking().FirstOrDefaultAsync(expression);
    }

    public async Task<IList<T>> GetAll(Expression<Func<T, bool>>? expression = null,
    Func<IQueryable<T>, IOrderedQueryable<T>>? orderBy = null, List<string>? includes = null)
    {
      IQueryable<T> query = _db;
      if (expression != null)
      {
        query = query.Where(expression);
      }

      if (includes != null)
      {
        foreach (var includeProp in includes)
        {
          query = query.Include(includeProp);
        }
      }

      if (orderBy != null)
      {
        query = orderBy(query);
      }

      return await query.AsNoTracking().ToListAsync() ?? new List<T>();
    }

    public async Task Create(T entity)
    {
      if (entity == null) throw new ArgumentNullException(nameof(entity));
      await _db.AddAsync(entity);
    }

    public async Task CreateRange(IEnumerable<T> entities)
    {
      if (entities == null) throw new ArgumentNullException(nameof(entities));
      await _db.AddRangeAsync(entities);
    }

    public async Task Delete(int id)
    {
      var entity = await _db.FindAsync(id);
      if (entity != null)
      {
        _db.Remove(entity);
      }
    }

    public void DeleteRange(IEnumerable<T> entities)
    {
      if (entities == null) throw new ArgumentNullException(nameof(entities));
      _db.RemoveRange(entities);
    }

    public void Delete(T entity)
    {
      if (entity == null) throw new ArgumentNullException(nameof(entity));
      _db.Remove(entity);
    }

    public void Update(T entity)
    {
      if (entity == null) throw new ArgumentNullException(nameof(entity));
      _db.Attach(entity);
      _ctx.Entry(entity).State = EntityState.Modified;
    }
  }
}
