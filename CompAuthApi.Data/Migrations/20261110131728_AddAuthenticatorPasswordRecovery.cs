using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompAuthApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAuthenticatorPasswordRecovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuthenticatorActionGrants",
                columns: table => new
                {
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    UserId = table.Column<int>(type: "int", nullable: false),
                    Purpose = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    PasswordFingerprint = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    SecretFingerprint = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ConsumedUtc = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthenticatorActionGrants", x => x.TokenHash);
                    table.ForeignKey(
                        name: "FK_AuthenticatorActionGrants_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AuthenticatorUsedSteps",
                columns: table => new
                {
                    UserId = table.Column<int>(type: "int", nullable: false),
                    TimeStep = table.Column<long>(type: "bigint", nullable: false),
                    Purpose = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    UsedUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthenticatorUsedSteps", x => new { x.UserId, x.TimeStep });
                    table.ForeignKey(
                        name: "FK_AuthenticatorUsedSteps_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PasswordRecoveryThrottles",
                columns: table => new
                {
                    KeyHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    WindowStartedUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    AttemptCount = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordRecoveryThrottles", x => x.KeyHash);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticatorActionGrants_UserId_Purpose_ExpiresUtc",
                table: "AuthenticatorActionGrants",
                columns: new[] { "UserId", "Purpose", "ExpiresUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuthenticatorActionGrants");

            migrationBuilder.DropTable(
                name: "AuthenticatorUsedSteps");

            migrationBuilder.DropTable(
                name: "PasswordRecoveryThrottles");
        }
    }
}
