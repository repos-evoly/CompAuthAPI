using System;
using System.Collections.Generic;
using System.Linq;
using CompAuthApi.Data.Models;
using CompAuthApi.Data.Context;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CompAuthApi.Data.Seeding
{
    public class DataSeeder
    {
        private readonly CompAuthApiDbContext _context;

        public DataSeeder(CompAuthApiDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public void Seed()
        {
            SeedRoles();
            SeedAdminUser();
            SeedSettings();
        }

        #region Role Seeding
        private void SeedRoles()
        {
            if (!_context.Roles.Any())
            {
                var roles = new List<Role>
                {
                    new() { TitleLT = "SuperAdmin"     }, // full system control
                    new() { TitleLT = "Admin"          }, // manage companies & settings
                    new() { TitleLT = "CompanyManager"        }, // monitor & troubleshoot
                    new() { TitleLT = "CompanyUser"        }, // compliance & read-only
                    new() { TitleLT = "CompanyAccountant" }, // top-level company authority
                    new() { TitleLT = "CompanyAuditor"     }, // financial operator
                    new() { TitleLT = "Maker"          }, // initiates transfers / requests
                    new() { TitleLT = "Checker"        }, // approves transfers / requests
                    new() { TitleLT = "Viewer"         }  // read-only company access
                };

                _context.Roles.AddRange(roles);
                _context.SaveChanges();
            }
        }
        #endregion

        #region Admin User Seeding
        private void SeedAdminUser()
        {
            if (!_context.Users.Any(u => u.Email == "admin@example.com"))
            {
                var adminRole = _context.Roles.FirstOrDefault(r => r.TitleLT == "Admin")?.Id ?? 1;

                var adminUser = new User
                {
                    Email = "admin@example.com",
                    Password = BCrypt.Net.BCrypt.HashPassword("123"), // Hash the password
                    Active = true,
                    RoleId = adminRole,
                    UserSecurity = new UserSecurity()
                };

                _context.Users.Add(adminUser);
                _context.SaveChanges();
            }
        }
        #endregion

        #region Settings Seeding
        private void SeedSettings()
        {
            if (!_context.Settings.Any())
            {
                var settings = new Settings
                {
                    IsTwoFactorAuthEnabled = false,      // Default value; adjust as needed.
                    IsRecaptchaEnabled = false,            // Default value; adjust as needed.
                    RecaptchaSiteKey = "YourRecaptchaSiteKey",   // Replace with your default key if needed.
                    RecaptchaSecretKey = "YourRecaptchaSecretKey", // Replace with your default secret if needed.
                    Url = "http://localhost:5000",         // Default URL.
                    Date = DateTime.UtcNow.ToString("yyyy-MM-dd") // Current UTC date in "yyyy-MM-dd" format.
                };

                _context.Settings.Add(settings);
                _context.SaveChanges();
            }
        }
        #endregion





        #region Public Method to Run Seeder
        public static void Initialize(IServiceProvider serviceProvider)
        {
            using var context = serviceProvider.GetRequiredService<CompAuthApiDbContext>();
            var seeder = new DataSeeder(context);
            seeder.Seed();
        }
        #endregion
    }
}
