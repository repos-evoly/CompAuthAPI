using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompAuthApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDynamicMobileApprovalPolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "MobileAccessPolicyUpdatedAt",
                table: "Settings",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "MobileAccessPolicyUpdatedBy",
                table: "Settings",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "MobileAccessPolicyVersion",
                table: "Settings",
                type: "int",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<bool>(
                name: "RequireApprovedMobileDevice",
                table: "Settings",
                type: "bit",
                nullable: false,
                defaultValue: true);

            migrationBuilder.AddColumn<bool>(
                name: "ApprovedDeviceAuthenticated",
                table: "DeviceSessions",
                type: "bit",
                nullable: false,
                defaultValue: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MobileAccessPolicyUpdatedAt",
                table: "Settings");

            migrationBuilder.DropColumn(
                name: "MobileAccessPolicyUpdatedBy",
                table: "Settings");

            migrationBuilder.DropColumn(
                name: "MobileAccessPolicyVersion",
                table: "Settings");

            migrationBuilder.DropColumn(
                name: "RequireApprovedMobileDevice",
                table: "Settings");

            migrationBuilder.DropColumn(
                name: "ApprovedDeviceAuthenticated",
                table: "DeviceSessions");
        }
    }
}
