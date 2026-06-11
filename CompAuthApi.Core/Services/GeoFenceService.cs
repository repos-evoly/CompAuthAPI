using System.Net;
using CompAuthApi.Core.Abstractions;
using CompAuthApi.Core.Dtos;
using CompAuthApi.Data.Context;
using CompAuthApi.Data.Models;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Exceptions;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace CompAuthApi.Core.Services
{
    public class GeoFenceService : IGeoFenceService
    {
        private const int DefaultCountrySwitchCooldownMinutes = 120;
        private const string DefaultGeoIpDatabasePath = "GeoIp/GeoLite2-Country.mmdb";

        private readonly CompAuthApiDbContext _db;
        private readonly IConfiguration _config;
        private readonly IHostEnvironment _environment;

        public GeoFenceService(
            CompAuthApiDbContext db,
            IConfiguration config,
            IHostEnvironment environment)
        {
            _db = db;
            _config = config;
            _environment = environment;
        }

        public async Task<GeoFenceEvaluationDto> EvaluateLoginAsync(
            User user,
            HttpContext httpContext,
            DateTimeOffset now,
            CancellationToken cancellationToken = default)
        {
            var settings = await GetSettingsAsync(cancellationToken);
            var clientIp = GetClientIpInfo(httpContext);
            var debug = new GeoFenceDebugInfoDto
            {
                XForwardedFor = clientIp.XForwardedFor,
                RemoteIpAddress = clientIp.RemoteIpAddress,
                ClientIp = clientIp.ClientIp,
                IsPrivateIp = clientIp.IsPrivateIp,
                ResolutionStatus = clientIp.ClientIp == null ? "missing_ip" : "pending"
            };

            var debugEnabled = ShouldExposeDebug(settings);
            var allowedResult = new GeoFenceEvaluationDto
            {
                IsEnabled = settings.IsEnabled,
                IsAllowed = true,
                ShouldExposeDebugClientIp = debugEnabled,
                DebugClientIp = debug
            };

            if (!settings.IsEnabled)
            {
                debug.ResolutionStatus = "geofence_disabled";
                return allowedResult;
            }

            if (string.IsNullOrWhiteSpace(clientIp.ClientIp))
            {
                debug.ResolutionStatus = "missing_ip";
                return allowedResult;
            }

            if (clientIp.IsPrivateIp && settings.BypassPrivateIps)
            {
                debug.ResolutionStatus = "private_ip_bypassed";
                return allowedResult;
            }

            var country = ResolveCountry(clientIp.ClientIp);
            debug.ResolvedCountryCode = country.CountryCode;
            debug.ResolvedCountryName = country.CountryName;
            debug.ResolutionStatus = country.Status;

            if (string.IsNullOrWhiteSpace(country.CountryCode))
            {
                if (!settings.BlockUnknownCountries)
                {
                    return allowedResult;
                }

                return BuildBlockedResult(
                    settings,
                    debug,
                    StatusCodes.Status403Forbidden,
                    "AUTH_GEOFENCE_COUNTRY_UNKNOWN",
                    "Login blocked because the login country could not be determined.",
                    "تم حظر تسجيل الدخول لأنه تعذر تحديد دولة تسجيل الدخول.",
                    new
                    {
                        clientIp = clientIp.ClientIp,
                        resolutionStatus = country.Status,
                        debugClientIp = debugEnabled ? debug : null
                    });
            }

            allowedResult.CurrentCountryCode = country.CountryCode;
            allowedResult.CurrentCountryName = country.CountryName;

            var lastSuccessfulLogin = await _db.UserLoginEvents
                .AsNoTracking()
                .Where(e =>
                    e.UserId == user.Id &&
                    e.IsSuccessful &&
                    e.CountryCode != null &&
                    e.CountryCode != "")
                .OrderByDescending(e => e.EventAt)
                .FirstOrDefaultAsync(cancellationToken);

            if (lastSuccessfulLogin == null)
            {
                return allowedResult;
            }

            var previousCountry = NormalizeCountryCode(lastSuccessfulLogin.CountryCode);
            var currentCountry = NormalizeCountryCode(country.CountryCode);
            if (string.Equals(previousCountry, currentCountry, StringComparison.OrdinalIgnoreCase))
            {
                return allowedResult;
            }

            var rule = await FindCountryRuleAsync(previousCountry, currentCountry, cancellationToken);
            if (rule != null && !rule.IsAllowed)
            {
                return BuildBlockedResult(
                    settings,
                    debug,
                    StatusCodes.Status403Forbidden,
                    "AUTH_GEOFENCE_COUNTRY_BLOCKED",
                    "Login blocked from this country pair.",
                    "تم حظر تسجيل الدخول بين هاتين الدولتين.",
                    new
                    {
                        previousCountry,
                        currentCountry,
                        lastLoginAt = lastSuccessfulLogin.EventAt,
                        ruleId = rule.Id,
                        debugClientIp = debugEnabled ? debug : null
                    });
            }

            var cooldownMinutes = rule?.CooldownMinutes > 0
                ? rule.CooldownMinutes
                : settings.DefaultCountrySwitchCooldownMinutes;
            if (cooldownMinutes <= 0)
            {
                cooldownMinutes = DefaultCountrySwitchCooldownMinutes;
            }

            var restrictedUntil = lastSuccessfulLogin.EventAt.AddMinutes(cooldownMinutes);
            if (now >= restrictedUntil)
            {
                return allowedResult;
            }

            return BuildBlockedResult(
                settings,
                debug,
                StatusCodes.Status403Forbidden,
                "AUTH_GEOFENCE_COUNTRY_SWITCH_BLOCKED",
                "Login blocked due to country change within the restricted time window.",
                "تم حظر تسجيل الدخول بسبب تغيير الدولة خلال الفترة الزمنية المقيدة.",
                new
                {
                    previousCountry,
                    currentCountry,
                    cooldownMinutes,
                    lastLoginAt = lastSuccessfulLogin.EventAt,
                    restrictedUntil,
                    ruleId = rule?.Id,
                    debugClientIp = debugEnabled ? debug : null
                });
        }

        public Task RecordLoginEventAsync(
            User user,
            GeoFenceEvaluationDto evaluation,
            DateTimeOffset now,
            bool isSuccessful,
            string? sessionId = null,
            string? failureCode = null,
            string? failureReason = null,
            CancellationToken cancellationToken = default)
        {
            var debug = evaluation.DebugClientIp;
            _db.UserLoginEvents.Add(new UserLoginEvent
            {
                UserId = user.Id,
                SessionId = TrimToLength(sessionId, 64),
                IpAddress = TrimToLength(debug?.ClientIp, 64),
                XForwardedFor = TrimToLength(debug?.XForwardedFor, 512),
                RemoteIpAddress = TrimToLength(debug?.RemoteIpAddress, 64),
                CountryCode = TrimToLength(evaluation.CurrentCountryCode ?? debug?.ResolvedCountryCode, 2),
                CountryName = TrimToLength(evaluation.CurrentCountryName ?? debug?.ResolvedCountryName, 128),
                IsSuccessful = isSuccessful,
                FailureCode = TrimToLength(failureCode ?? evaluation.FailureCode, 128),
                FailureReason = TrimToLength(failureReason ?? evaluation.FailureReason, 512),
                EventAt = now
            });

            return Task.CompletedTask;
        }

        private async Task<GeoFenceSetting> GetSettingsAsync(CancellationToken cancellationToken)
        {
            var settings = await _db.GeoFenceSettings
                .AsNoTracking()
                .OrderBy(s => s.Id)
                .FirstOrDefaultAsync(cancellationToken);

            return settings ?? new GeoFenceSetting
            {
                IsEnabled = true,
                DefaultCountrySwitchCooldownMinutes = DefaultCountrySwitchCooldownMinutes,
                DebugExposeClientIp = false,
                BypassPrivateIps = true,
                BlockUnknownCountries = false
            };
        }

        private bool ShouldExposeDebug(GeoFenceSetting settings)
        {
            return settings.DebugExposeClientIp || _config.GetValue<bool>("GeoFence:DebugExposeClientIp");
        }

        private async Task<GeoFenceCountryRule?> FindCountryRuleAsync(
            string? previousCountry,
            string? currentCountry,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(previousCountry) || string.IsNullOrWhiteSpace(currentCountry))
            {
                return null;
            }

            return await _db.GeoFenceCountryRules
                .AsNoTracking()
                .Where(r =>
                    r.IsActive &&
                    ((r.FromCountryCode == previousCountry && r.ToCountryCode == currentCountry) ||
                     (r.FromCountryCode == currentCountry && r.ToCountryCode == previousCountry)))
                .OrderByDescending(r => r.Id)
                .FirstOrDefaultAsync(cancellationToken);
        }

        private GeoFenceEvaluationDto BuildBlockedResult(
            GeoFenceSetting settings,
            GeoFenceDebugInfoDto debug,
            int status,
            string code,
            string messageEn,
            string messageAr,
            object details)
        {
            return new GeoFenceEvaluationDto
            {
                IsEnabled = settings.IsEnabled,
                IsAllowed = false,
                FailureCode = code,
                FailureReason = messageEn,
                CurrentCountryCode = debug.ResolvedCountryCode,
                CurrentCountryName = debug.ResolvedCountryName,
                ShouldExposeDebugClientIp = ShouldExposeDebug(settings),
                DebugClientIp = debug,
                Error = new AuthApiErrorResponseDto
                {
                    Success = false,
                    Status = status,
                    Code = code,
                    Message = messageEn,
                    MessageEn = messageEn,
                    MessageAr = messageAr,
                    Details = details
                }
            };
        }

        private GeoCountryLookupResult ResolveCountry(string ipAddress)
        {
            var databasePath = ResolveDatabasePath();
            if (databasePath == null)
            {
                return new GeoCountryLookupResult(null, null, "geoip_database_missing");
            }

            try
            {
                using var reader = new DatabaseReader(databasePath);
                var response = reader.Country(ipAddress);
                var country = response.Country ?? response.RegisteredCountry ?? response.RepresentedCountry;
                return new GeoCountryLookupResult(
                    NormalizeCountryCode(country?.IsoCode),
                    country?.Name,
                    "resolved");
            }
            catch (AddressNotFoundException)
            {
                return new GeoCountryLookupResult(null, null, "address_not_found");
            }
            catch (Exception ex)
            {
                return new GeoCountryLookupResult(null, null, $"lookup_failed:{ex.GetType().Name}");
            }
        }

        private string? ResolveDatabasePath()
        {
            var configuredPath = _config["GeoFence:GeoIpDatabasePath"];
            if (string.IsNullOrWhiteSpace(configuredPath))
            {
                configuredPath = DefaultGeoIpDatabasePath;
            }

            var candidates = Path.IsPathRooted(configuredPath)
                ? new[] { configuredPath }
                : new[]
                {
                    Path.Combine(_environment.ContentRootPath, configuredPath),
                    Path.Combine(AppContext.BaseDirectory, configuredPath),
                    Path.Combine(_environment.ContentRootPath, "..", configuredPath)
                };

            return candidates
                .Select(Path.GetFullPath)
                .FirstOrDefault(File.Exists);
        }

        private static ClientIpInfo GetClientIpInfo(HttpContext httpContext)
        {
            var xForwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            var remoteIp = httpContext.Connection.RemoteIpAddress?.ToString();
            var selectedIp = !string.IsNullOrWhiteSpace(xForwardedFor)
                ? xForwardedFor.Split(',').FirstOrDefault()?.Trim()
                : remoteIp;

            return new ClientIpInfo(
                TrimToLength(xForwardedFor, 512),
                TrimToLength(remoteIp, 64),
                TrimToLength(selectedIp, 64),
                IsPrivateOrLocalIp(selectedIp));
        }

        private static bool IsPrivateOrLocalIp(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || !IPAddress.TryParse(value, out var ipAddress))
            {
                return false;
            }

            if (IPAddress.IsLoopback(ipAddress))
            {
                return true;
            }

            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = ipAddress.GetAddressBytes();
                return bytes[0] == 10 ||
                       (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                       (bytes[0] == 192 && bytes[1] == 168);
            }

            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return ipAddress.IsIPv6LinkLocal ||
                       ipAddress.IsIPv6SiteLocal ||
                       value.Equals("::1", StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        private static string? NormalizeCountryCode(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            var normalized = value.Trim().ToUpperInvariant();
            return normalized.Length <= 2 ? normalized : normalized[..2];
        }

        private static string? TrimToLength(string? value, int maxLength)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            var trimmed = value.Trim();
            return trimmed.Length <= maxLength ? trimmed : trimmed[..maxLength];
        }

        private sealed record ClientIpInfo(
            string? XForwardedFor,
            string? RemoteIpAddress,
            string? ClientIp,
            bool IsPrivateIp);

        private sealed record GeoCountryLookupResult(
            string? CountryCode,
            string? CountryName,
            string Status);
    }
}
