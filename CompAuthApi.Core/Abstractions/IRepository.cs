using System.Linq.Expressions;

namespace CompAuthApi.Core.Abstractions
{
    public interface IRepository<T> where T : class
    {
        Task<IList<T>> GetAll(
            Expression<Func<T, bool>>? expression = null, // Marked nullable
            Func<IQueryable<T>, IOrderedQueryable<T>>? orderBy = null, // Marked nullable
            List<string>? includes = null // Marked nullable
        );

        Task<T?> GetById(Expression<Func<T, bool>> expression, List<string>? includes = null); // Marked includes nullable and return type nullable
        Task Create(T entity);
        Task CreateRange(IEnumerable<T> entities);
        void Delete(T entity);
        void DeleteRange(IEnumerable<T> entities);
        void Update(T entity);
    }
}
