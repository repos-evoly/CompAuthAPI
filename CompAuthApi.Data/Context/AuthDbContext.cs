using CompAuthApi.Data.Models;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System;

namespace CompAuthApi.Data.Context
{
    public class CompAuthApiDbContext : DbContext
    {
        public CompAuthApiDbContext(DbContextOptions<CompAuthApiDbContext> options) : base(options) { }
        public CompAuthApiDbContext() { }


        public DbSet<User> Users => Set<User>();
        public DbSet<Role> Roles => Set<Role>();

        public DbSet<UserSecurity> UserSecurities => Set<UserSecurity>();
        public DbSet<Settings> Settings => Set<Settings>();
        public DbSet<UserSession> UserSessions => Set<UserSession>();
        public DbSet<GeoFenceSetting> GeoFenceSettings => Set<GeoFenceSetting>();
        public DbSet<GeoFenceCountryRule> GeoFenceCountryRules => Set<GeoFenceCountryRule>();
        public DbSet<UserLoginEvent> UserLoginEvents => Set<UserLoginEvent>();
        public DbSet<MobileDevice> MobileDevices => Set<MobileDevice>();
        public DbSet<DeviceActivationCode> DeviceActivationCodes => Set<DeviceActivationCode>();
        public DbSet<DeviceChallenge> DeviceChallenges => Set<DeviceChallenge>();
        public DbSet<DeviceSession> DeviceSessions => Set<DeviceSession>();
        public DbSet<DeviceLoginGrant> DeviceLoginGrants => Set<DeviceLoginGrant>();
        public DbSet<MobilePushToken> MobilePushTokens => Set<MobilePushToken>();

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseSqlServer("Server=10.3.3.11,1433;Database=CompAuthDb;User Id=ccadmin;Password=ccadmin;Trusted_Connection=False;MultipleActiveResultSets=true;TrustServerCertificate=True;");
            }
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<User>().HasIndex(u => u.Email).IsUnique().HasDatabaseName("Unique_Email");


            builder.Entity<User>()
                .HasOne(u => u.Role)
                .WithMany(r => r.Users)
                .HasForeignKey(u => u.RoleId)
                .OnDelete(DeleteBehavior.Restrict);

            builder.Entity<User>()
                .HasOne(u => u.UserSecurity)
                .WithOne(us => us.User)
                .HasForeignKey<UserSecurity>(us => us.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<UserSession>()
                .HasOne(s => s.User)
                .WithMany(u => u.UserSessions)
                .HasForeignKey(s => s.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<UserLoginEvent>()
                .HasOne(e => e.User)
                .WithMany(u => u.LoginEvents)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<MobileDevice>()
                .Property(device => device.Status)
                .HasConversion<string>()
                .HasMaxLength(16);

            builder.Entity<DeviceChallenge>()
                .HasOne(challenge => challenge.ActivationCode)
                .WithMany()
                .HasForeignKey(challenge => challenge.ActivationCodeId)
                .OnDelete(DeleteBehavior.Restrict);

            builder.Entity<DeviceChallenge>()
                .HasOne(challenge => challenge.MobileDevice)
                .WithMany(device => device.Challenges)
                .HasForeignKey(challenge => challenge.MobileDeviceId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<DeviceSession>()
                .HasOne(session => session.MobileDevice)
                .WithMany(device => device.DeviceSessions)
                .HasForeignKey(session => session.MobileDeviceId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<DeviceLoginGrant>()
                .HasOne(grant => grant.MobileDevice)
                .WithMany(device => device.LoginGrants)
                .HasForeignKey(grant => grant.MobileDeviceId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<MobilePushToken>()
                .HasOne(token => token.MobileDevice)
                .WithOne(device => device.PushToken)
                .HasForeignKey<MobilePushToken>(token => token.MobileDeviceId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<UserSecurity>().HasIndex(us => us.TwoFactorSecretKey).IsUnique();

            builder.Entity<Settings>()
               .HasIndex(s => s.Id)
               .IsUnique();

            builder.Entity<GeoFenceSetting>()
               .HasIndex(s => s.Id)
               .IsUnique();
        }


        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            var insertedEntries = this.ChangeTracker.Entries()
                         .Where(x => x.State == EntityState.Added)
                         .Select(x => x.Entity);

            foreach (var insertedEntry in insertedEntries)
            {
                var auditableEntity = insertedEntry as Auditable;
                //If the inserted object is an Auditable. 
                if (auditableEntity != null)
                {
                    auditableEntity.CreatedAt = DateTimeOffset.Now;
                    auditableEntity.UpdatedAt = DateTimeOffset.Now;
                }
            }

            var modifiedEntries = this.ChangeTracker.Entries()
                   .Where(x => x.State == EntityState.Modified)
                   .Select(x => x.Entity);

            foreach (var modifiedEntry in modifiedEntries)
            {
                //If the inserted object is an Auditable. 
                var auditableEntity = modifiedEntry as Auditable;
                if (auditableEntity != null)
                {
                    auditableEntity.UpdatedAt = DateTimeOffset.Now;
                }
            }

            return base.SaveChangesAsync(cancellationToken);
        }
    }
}
