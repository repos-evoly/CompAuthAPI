using CompAuthApi.Core.Dtos;
using CompAuthApi.Data.Models;
using Microsoft.AspNetCore.Http;

namespace CompAuthApi.Core.Abstractions
{
    public interface IGeoFenceService
    {
        Task<GeoFenceEvaluationDto> EvaluateLoginAsync(
            User user,
            HttpContext httpContext,
            DateTimeOffset now,
            CancellationToken cancellationToken = default);

        Task RecordLoginEventAsync(
            User user,
            GeoFenceEvaluationDto evaluation,
            DateTimeOffset now,
            bool isSuccessful,
            string? sessionId = null,
            string? failureCode = null,
            string? failureReason = null,
            CancellationToken cancellationToken = default);
    }
}
