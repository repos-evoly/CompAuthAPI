using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompAuthApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class MobileDeviceAuthentication : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeviceActivationCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CodeHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    TargetAuthUserId = table.Column<int>(type: "int", nullable: false),
                    LoginHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    CreatedByAuthUserId = table.Column<int>(type: "int", nullable: false),
                    CompanyCode = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    UsedByDeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceActivationCodes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MobileDevices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    InstallationId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    TargetAuthUserId = table.Column<int>(type: "int", nullable: false),
                    LoginHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    CompanyCode = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    Platform = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    AppVersion = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    KeyAlgorithm = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    PublicKeyPem = table.Column<string>(type: "nvarchar(max)", maxLength: 4096, nullable: false),
                    PublicKeyFingerprint = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    AttestationProvider = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    AttestationStatus = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    ProofVerifiedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ApprovedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ApprovedByAuthUserId = table.Column<int>(type: "int", nullable: true),
                    RevokedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RevokedByAuthUserId = table.Column<int>(type: "int", nullable: true),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MobileDevices", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeviceChallenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    MobileDeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ActivationCodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Purpose = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Nonce = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeviceChallenges_DeviceActivationCodes_ActivationCodeId",
                        column: x => x.ActivationCodeId,
                        principalTable: "DeviceActivationCodes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_DeviceChallenges_MobileDevices_MobileDeviceId",
                        column: x => x.MobileDeviceId,
                        principalTable: "MobileDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeviceLoginGrants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    MobileDeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ChallengeTokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    LoginHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceLoginGrants", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeviceLoginGrants_MobileDevices_MobileDeviceId",
                        column: x => x.MobileDeviceId,
                        principalTable: "MobileDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeviceSessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    MobileDeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AuthUserId = table.Column<int>(type: "int", nullable: false),
                    CompAuthSessionId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    RevokedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceSessions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeviceSessions_MobileDevices_MobileDeviceId",
                        column: x => x.MobileDeviceId,
                        principalTable: "MobileDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceActivationCodes_CodeHash",
                table: "DeviceActivationCodes",
                column: "CodeHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeviceActivationCodes_CompanyCode_ExpiresAt",
                table: "DeviceActivationCodes",
                columns: new[] { "CompanyCode", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceChallenges_ActivationCodeId",
                table: "DeviceChallenges",
                column: "ActivationCodeId");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceChallenges_MobileDeviceId_Purpose_ExpiresAt",
                table: "DeviceChallenges",
                columns: new[] { "MobileDeviceId", "Purpose", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceLoginGrants_ChallengeTokenHash",
                table: "DeviceLoginGrants",
                column: "ChallengeTokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeviceLoginGrants_MobileDeviceId_ExpiresAt",
                table: "DeviceLoginGrants",
                columns: new[] { "MobileDeviceId", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceSessions_CompAuthSessionId_RevokedAt",
                table: "DeviceSessions",
                columns: new[] { "CompAuthSessionId", "RevokedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceSessions_MobileDeviceId_RevokedAt",
                table: "DeviceSessions",
                columns: new[] { "MobileDeviceId", "RevokedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceSessions_TokenHash",
                table: "DeviceSessions",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MobileDevices_CompanyCode_Status",
                table: "MobileDevices",
                columns: new[] { "CompanyCode", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_MobileDevices_InstallationId",
                table: "MobileDevices",
                column: "InstallationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MobileDevices_TargetAuthUserId_Status",
                table: "MobileDevices",
                columns: new[] { "TargetAuthUserId", "Status" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeviceChallenges");

            migrationBuilder.DropTable(
                name: "DeviceLoginGrants");

            migrationBuilder.DropTable(
                name: "DeviceSessions");

            migrationBuilder.DropTable(
                name: "DeviceActivationCodes");

            migrationBuilder.DropTable(
                name: "MobileDevices");
        }
    }
}
