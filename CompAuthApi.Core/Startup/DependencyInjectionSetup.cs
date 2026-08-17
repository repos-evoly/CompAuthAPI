using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CompAuthApi.Data.Context;
using CompAuthApi.Core.Dtos;
using CompAuthApi.Validators;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using CompAuthApi.Core.Filters;
using CompAuthApi.Core.Repositories;
using CompAuthApi.Core.Services;
using Microsoft.AspNetCore.Builder;
using CompAuthApi.Core.Abstractions;
using Microsoft.Extensions.Hosting;
using CompAuthApi.Data.Seeding;
using CompAuthApi.Data.Repositories;
using CompAuthApi.Core.Authentication;
using CompAuthApi.Core.Devices;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

namespace CompAuthApi.Core.Startup
{
  public static class DependencyInjectionSetup
  {
    public static WebApplicationBuilder RegisterServices(this WebApplicationBuilder builder)
    {
      var issuer = builder.Configuration["Jwt:Issuer"] ?? throw new ArgumentNullException("Jwt:Issuer is missing in configuration.");
      var audience = builder.Configuration["Jwt:Audience"] ?? throw new ArgumentNullException("Jwt:Audience is missing in configuration.");
      var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new ArgumentNullException("Jwt:Key is missing in configuration.");

      builder.Services.RegisterCors();
      builder.Services.RegisterSwagger();
      builder.Services.RegisterAuths(issuer, audience, jwtKey);
      builder.Services.RegisterMobileServiceAuthentication(builder.Configuration);
      builder.Services.RegisterMobileAuthRateLimits();
      builder.Services
        .AddOptions<DeviceSecurityOptions>()
        .Bind(builder.Configuration.GetSection(DeviceSecurityOptions.SectionName));
      builder.Services.AddScoped<IDeviceSecurityService, DeviceSecurityService>();
      builder.Services.AddScoped<IDeviceAdministrationService, DeviceAdministrationService>();
      builder.Services.AddScoped<IDeviceAttestationValidator, DeviceAttestationValidator>();
      builder.Services.AddScoped<IMobilePushTokenService, MobilePushTokenService>();
      if (builder.Environment.IsDevelopment())
      {
        builder.Services.AddDbContext<CompAuthApiDbContext>(opt =>
            opt.UseSqlServer(
              builder.Configuration["ConnectionStrings:DevConnection"],
              x => x.EnableRetryOnFailure(maxRetryCount: 5, maxRetryDelay: TimeSpan.FromSeconds(10), errorNumbersToAdd: null)
            ));
      }
      else if (builder.Environment.IsStaging())
      {
        builder.Services.AddDbContext<CompAuthApiDbContext>(opt =>
            opt.UseSqlServer(
              builder.Configuration["ConnectionStrings:StagingConnection"],
              x => x.EnableRetryOnFailure(maxRetryCount: 5, maxRetryDelay: TimeSpan.FromSeconds(10), errorNumbersToAdd: null)
            ));
      }
      else
      {
        builder.Services.AddDbContext<CompAuthApiDbContext>(opt =>
            opt.UseSqlServer(
              builder.Configuration["ConnectionStrings:ProdConnection"],
              x => x.EnableRetryOnFailure(maxRetryCount: 5, maxRetryDelay: TimeSpan.FromSeconds(10), errorNumbersToAdd: null)
            ));
      }
      builder.Services.AddHttpContextAccessor();
      builder.Services.AddTransient<DataSeeder>();
      builder.Services.AddAutoMapper(typeof(MappingConfig));
      builder.Services.Configure<JsonOptions>(options =>
      {
        options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.SerializerOptions.WriteIndented = true;
        options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
        options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
      });

      builder.Services.RegisterValidators();
      builder.Services.RegisterRepos();
      return builder;
    }

    public static IServiceCollection RegisterCors(this IServiceCollection cors)
    {
      cors.AddCors(options =>
            {
              options.AddPolicy("AllowSpecificOrigins",
                    builder =>
                    {
                      builder.WithOrigins("http://localhost",
                                          "http://10.3.3.11",
                                          "http://localhost:3000",
                                          "http://localhost:3012",
                                          "http://10.3.3.11:3012",
                                          "http://10.3.3.11:3013",
                                          "http://localhost:3012",
                                          "http://10.3.3.11:3012",
                                          "http://localhost:5000",
                                          "http://10.1.1.205",
                                          "http://10.1.1.205:3012",
                                          "http://192.168.0.245:3012",
                                          "http://192.168.0.245:3013",
                                          "http://192.168.113.10",
                                          "http://192.168.113.10:3012",
                                          "http://192.168.113.11",
                                          "http://192.168.113.11:3012",
                                          "http://10.1.1.205:3012",
                                          "http://10.1.1.205:3013",
                                          "http://localhost:3013",
                                          "https://webanking.bcd.ly/Companygw",
                                          "http://10.1.1.205:3013")
                             .AllowAnyHeader()
                             .AllowAnyMethod()
                             .AllowCredentials();
                    });
            });
      return cors;
    }

    public static IServiceCollection RegisterAuths(this IServiceCollection auth, string issuer, string audience, string jwtKey)
    {
      auth.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
      .AddCookie(options =>
      {
        options.Cookie.Name = "AuthToken";
      })
      .AddJwtBearer(options =>
            {
              options.RequireHttpsMetadata = false;
              options.SaveToken = true;
              options.TokenValidationParameters = new TokenValidationParameters()
              {
                ValidateActor = true,
                ValidateAudience = true,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
              };
              options.Events = new JwtBearerEvents
              {
                OnMessageReceived = context =>
                {
                  if (context.Request.Cookies.ContainsKey("AuthToken"))
                  {
                    context.Token = context.Request.Cookies["AuthToken"];
                  }
                  return Task.CompletedTask;
                },
                OnTokenValidated = async context =>
                {
                  const string sessionIdClaimType = "sessionId";
                  const int idleSessionMinutes = 5;

                  var sessionId = context.Principal?.FindFirst(sessionIdClaimType)?.Value;
                  if (string.IsNullOrWhiteSpace(sessionId))
                  {
                    context.Fail("Authentication session is missing.");
                    return;
                  }

                  var db = context.HttpContext.RequestServices.GetRequiredService<CompAuthApiDbContext>();
                  var now = DateTimeOffset.UtcNow;
                  var cutoff = now.AddMinutes(-idleSessionMinutes);

                  var session = await db.UserSessions.FirstOrDefaultAsync(s => s.SessionId == sessionId);
                  if (session == null ||
                      !session.IsActive ||
                      session.LoggedOutAt != null ||
                      session.ExpiresAt <= now ||
                      session.LastSeenAt <= cutoff)
                  {
                    if (session != null && session.IsActive)
                    {
                      session.IsActive = false;
                      await db.SaveChangesAsync();
                    }

                    context.Fail("Authentication session is expired or inactive.");
                  }
                },
                // The below should be uncommented in case the above "ValidateLifetime = true"
                // OnAuthenticationFailed = context =>
                // {
                //   if (context.Exception is SecurityTokenExpiredException)
                //   {
                //     // Handle token expiration
                //     context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                //     context.Response.ContentType = "application/json";
                //     context.Response.WriteAsync(JsonSerializer.Serialize(new Error
                //     {
                //       StatusCode = StatusCodes.Status401Unauthorized,
                //       Message = "Expired token. Please logout and then login."
                //     })).Wait(); // Use .Wait() to write the response immediately
                //     return Task.CompletedTask;
                //   }
                //   return Task.CompletedTask;
                // }
              };
            });
      // Define the set or roles in policies
      auth.AddAuthorization(a =>
      {
        a.AddPolicy("requireAuthUser", b => b
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
              .RequireAuthenticatedUser());
        a.AddPolicy("AdmMak", b => b.RequireRole("SuperAdmin", "Admin", "Maker"));
        a.AddPolicy("AdmChk", b => b.RequireRole("SuperAdmin", "Admin", "Checker", "GeneralChecker"));
        a.AddPolicy("AdmMakChk", b => b.RequireRole("SuperAdmin", "Admin", "Maker", "Checker", "GeneralChecker"));
        a.AddPolicy("AdmViwChk", b => b.RequireRole("SuperAdmin", "Admin", "Viewer", "Checker", "GeneralChecker"));
      });
      return auth;
    }

    public static IServiceCollection RegisterMobileServiceAuthentication(
      this IServiceCollection services,
      IConfiguration configuration)
    {
      services
        .AddOptions<ServiceTokenOptions>()
        .Bind(configuration.GetSection(ServiceTokenOptions.SectionName));
      services.AddSingleton(TimeProvider.System);
      services.AddSingleton<ServiceTokenService>();
      services.AddSingleton<IServiceTokenService>(provider =>
        provider.GetRequiredService<ServiceTokenService>());
      services.AddSingleton<IMobileAuthChallengeService>(provider =>
        provider.GetRequiredService<ServiceTokenService>());

      services.AddAuthentication()
        .AddScheme<AuthenticationSchemeOptions, ServiceTokenAuthenticationHandler>(
          ServiceAuthenticationDefaults.Scheme,
          _ => { });

      services.AddAuthorization(options =>
      {
        options.AddPolicy(
          ServiceAuthenticationDefaults.RequireMobileBffServicePolicy,
          policy => policy
            .AddAuthenticationSchemes(ServiceAuthenticationDefaults.Scheme)
            .RequireAuthenticatedUser()
            .RequireClaim(
              "token_type",
              ServiceAuthenticationDefaults.ServiceTokenType));

        options.AddPolicy(
          ServiceAuthenticationDefaults.RequireCompanyUserAndMobileBffServicePolicy,
          policy => policy
            .AddAuthenticationSchemes(
              JwtBearerDefaults.AuthenticationScheme,
              ServiceAuthenticationDefaults.Scheme)
            .RequireAssertion(context =>
              context.User.HasClaim(
                "token_type",
                ServiceAuthenticationDefaults.ServiceTokenType) &&
              context.User.HasClaim(claim =>
                claim.Type == "sessionId" &&
                !string.IsNullOrWhiteSpace(claim.Value)) &&
              context.User.HasClaim(claim =>
                claim.Type == System.Security.Claims.ClaimTypes.NameIdentifier &&
                !string.IsNullOrWhiteSpace(claim.Value))));
      });

      return services;
    }

    public static IServiceCollection RegisterMobileAuthRateLimits(
      this IServiceCollection services)
    {
      services.AddRateLimiter(options =>
      {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.AddFixedWindowLimiter("service-auth-token", limiter =>
        {
          limiter.PermitLimit = 10;
          limiter.Window = TimeSpan.FromMinutes(1);
          limiter.QueueLimit = 0;
          limiter.AutoReplenishment = true;
        });
        options.AddFixedWindowLimiter("mobile-auth-sensitive", limiter =>
        {
          limiter.PermitLimit = 60;
          limiter.Window = TimeSpan.FromMinutes(1);
          limiter.QueueLimit = 0;
          limiter.AutoReplenishment = true;
        });
        options.AddFixedWindowLimiter("mobile-auth-standard", limiter =>
        {
          limiter.PermitLimit = 240;
          limiter.Window = TimeSpan.FromMinutes(1);
          limiter.QueueLimit = 0;
          limiter.AutoReplenishment = true;
        });
      });

      return services;
    }

    public static IServiceCollection RegisterValidators(this IServiceCollection validators)
    {
      return validators;
    }

    public static IServiceCollection RegisterRepos(this IServiceCollection services)
    {
      services.AddEndpointsApiExplorer();
      services.AddScoped(typeof(IRepository<>), typeof(Repository<>));
      services.AddScoped<IQrCodeRepository, QrCodeRepository>();
      services.AddScoped<IAuthRepository, AuthRepository>();
      services.AddScoped<IGeoFenceService, GeoFenceService>();
      services.AddTransient<IUnitOfWork, UnitOfWork>();

      return services;
    }


    public static IServiceCollection RegisterSwagger(this IServiceCollection services)
    {
      services.AddSwaggerGen(options =>
          {
            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
              Scheme = "Bearer",
              BearerFormat = "JWT",
              In = ParameterLocation.Header,
              Name = "Authorization",
              Description = "Bearer Authentication with JWT Token",
              Type = SecuritySchemeType.Http
            });
            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
              {
                new OpenApiSecurityScheme
                {
                  Reference = new OpenApiReference
                  {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                  }
                },
                new List<string>()
              }
            });
            options.OperationFilter<FileUploadOperationFilter>();
          });

      return services;
    }
  }
}
