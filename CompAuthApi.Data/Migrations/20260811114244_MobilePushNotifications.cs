using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompAuthApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class MobilePushNotifications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "MobilePushTokens",
                columns: table => new
                {
                    MobileDeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AuthUserId = table.Column<int>(type: "int", nullable: false),
                    Token = table.Column<string>(type: "nvarchar(max)", maxLength: 4096, nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Platform = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    AppVersion = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MobilePushTokens", x => x.MobileDeviceId);
                    table.ForeignKey(
                        name: "FK_MobilePushTokens_MobileDevices_MobileDeviceId",
                        column: x => x.MobileDeviceId,
                        principalTable: "MobileDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MobilePushTokens_AuthUserId",
                table: "MobilePushTokens",
                column: "AuthUserId");

            migrationBuilder.CreateIndex(
                name: "IX_MobilePushTokens_TokenHash",
                table: "MobilePushTokens",
                column: "TokenHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MobilePushTokens");
        }
    }
}
