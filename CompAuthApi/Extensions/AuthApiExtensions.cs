using CompAuthApi.Abstractions;

namespace CompAuthApi.Extensions
{
  public static class EndpointsRegistration
  {
    public static void RegisterEndpoints(this WebApplication app)
    {
      var endpoints = typeof(Program).Assembly
                .GetTypes()
                .Where(t => t.IsAssignableTo(typeof(IEndpoints)) && !t.IsAbstract && !t.IsInterface)
                .Select(Activator.CreateInstance)
                .Cast<IEndpoints>();
      foreach (var endpoint in endpoints)
      {
        endpoint.RegisterEndpoints(app);
      }
    }
  }
}