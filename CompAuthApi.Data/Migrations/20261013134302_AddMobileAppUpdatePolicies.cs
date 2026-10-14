using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace CompAuthApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddMobileAppUpdatePolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "MobileAppUpdatePolicies",
                columns: table => new
                {
                    Platform = table.Column<string>(type: "nvarchar(7)", maxLength: 7, nullable: false),
                    Enabled = table.Column<bool>(type: "bit", nullable: false),
                    MinimumVersion = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    MinimumBuild = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    StoreUrl = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    MessageEn = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    MessageAr = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    Revision = table.Column<int>(type: "int", nullable: false),
                    UpdatedBy = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MobileAppUpdatePolicies", x => x.Platform);
                });

            migrationBuilder.InsertData(
                table: "MobileAppUpdatePolicies",
                columns: new[] { "Platform", "Enabled", "MessageAr", "MessageEn", "MinimumBuild", "MinimumVersion", "Revision", "StoreUrl", "UpdatedAt", "UpdatedBy" },
                values: new object[,]
                {
                    { "android", false, "يرجى تحديث التطبيق للمتابعة.", "Please update the app to continue.", "0", "1.0.0", 1, "https://play.google.com/store/apps/details?id=com.bcd.companygateway", null, null },
                    { "ios", false, "يرجى تحديث التطبيق للمتابعة.", "Please update the app to continue.", "0", "1.0.0", 1, "", null, null }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MobileAppUpdatePolicies");
        }
    }
}
