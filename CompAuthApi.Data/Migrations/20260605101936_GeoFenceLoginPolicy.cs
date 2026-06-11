using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompAuthApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class GeoFenceLoginPolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "GeoFenceCountryRules",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    FromCountryCode = table.Column<string>(type: "nvarchar(2)", maxLength: 2, nullable: false),
                    ToCountryCode = table.Column<string>(type: "nvarchar(2)", maxLength: 2, nullable: false),
                    CooldownMinutes = table.Column<int>(type: "int", nullable: false),
                    IsAllowed = table.Column<bool>(type: "bit", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GeoFenceCountryRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "GeoFenceSettings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    DefaultCountrySwitchCooldownMinutes = table.Column<int>(type: "int", nullable: false),
                    DebugExposeClientIp = table.Column<bool>(type: "bit", nullable: false),
                    BypassPrivateIps = table.Column<bool>(type: "bit", nullable: false),
                    BlockUnknownCountries = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GeoFenceSettings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserLoginEvents",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<int>(type: "int", nullable: false),
                    SessionId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    IpAddress = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    XForwardedFor = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    RemoteIpAddress = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    CountryCode = table.Column<string>(type: "nvarchar(2)", maxLength: 2, nullable: true),
                    CountryName = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    IsSuccessful = table.Column<bool>(type: "bit", nullable: false),
                    FailureCode = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    FailureReason = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    EventAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserLoginEvents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserLoginEvents_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "GeoFenceSettings",
                columns: new[]
                {
                    "Id",
                    "IsEnabled",
                    "DefaultCountrySwitchCooldownMinutes",
                    "DebugExposeClientIp",
                    "BypassPrivateIps",
                    "BlockUnknownCountries",
                    "CreatedAt",
                    "UpdatedAt"
                },
                values: new object[]
                {
                    1,
                    true,
                    120,
                    false,
                    true,
                    false,
                    new DateTimeOffset(2026, 6, 5, 0, 0, 0, TimeSpan.Zero),
                    new DateTimeOffset(2026, 6, 5, 0, 0, 0, TimeSpan.Zero)
                });

            migrationBuilder.CreateIndex(
                name: "IX_GeoFenceCountryRules_CountryPair",
                table: "GeoFenceCountryRules",
                columns: new[] { "FromCountryCode", "ToCountryCode", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_GeoFenceSettings_Id",
                table: "GeoFenceSettings",
                column: "Id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserLoginEvents_User_Success_Time",
                table: "UserLoginEvents",
                columns: new[] { "UserId", "IsSuccessful", "EventAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "GeoFenceCountryRules");

            migrationBuilder.DropTable(
                name: "GeoFenceSettings");

            migrationBuilder.DropTable(
                name: "UserLoginEvents");
        }
    }
}
