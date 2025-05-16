namespace CompAuthApi.Core.Extensions;

public static class IsNullEmptyEnumerableExtension
{
  public static bool IsNullOrEmpty<T>(this IEnumerable<T> enumerable)
  {
    return enumerable == null || !enumerable.Any();
  }
}