using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompAuthApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddMobileAppMaintenancePolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "MobileAppMaintenancePolicy",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false),
                    Enabled = table.Column<bool>(type: "bit", nullable: false),
                    MessageEn = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    MessageAr = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    Revision = table.Column<int>(type: "int", nullable: false),
                    UpdatedBy = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MobileAppMaintenancePolicy", x => x.Id);
                    table.CheckConstraint("CK_MobileAppMaintenancePolicy_Singleton", "[Id] = 1");
                });

            migrationBuilder.InsertData(
                table: "MobileAppMaintenancePolicy",
                columns: new[] { "Id", "Enabled", "MessageAr", "MessageEn", "Revision", "UpdatedAt", "UpdatedBy" },
                values: new object[] { 1, false, "التطبيق غير متاح مؤقتاً للصيانة. يرجى المحاولة لاحقاً.", "The app is temporarily unavailable for maintenance. Please try again later.", 1, null, null });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MobileAppMaintenancePolicy");
        }
    }
}
