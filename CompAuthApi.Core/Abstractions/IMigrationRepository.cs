using CompAuthApi.Core.Dtos;
using CompAuthApi.Data.Models;
using Microsoft.AspNetCore.Http;

namespace CompAuthApi.Core.Abstractions
{
  public interface IMigrationRepository
  {
    public string GetRawData();
    public string CleanData();
    public Task<string> MigrateCustomers();
    public string MigrateCustomerRelatedData();
  }
}
