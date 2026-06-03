using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompAuthApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class AccountLocking : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsLocked",
                table: "UserSecurity",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastLock",
                table: "UserSecurity",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "LoginAttemptCount",
                table: "UserSecurity",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "LockTimeoutMinutes",
                table: "Settings",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "MaxLoginAttempts",
                table: "Settings",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsLocked",
                table: "UserSecurity");

            migrationBuilder.DropColumn(
                name: "LastLock",
                table: "UserSecurity");

            migrationBuilder.DropColumn(
                name: "LoginAttemptCount",
                table: "UserSecurity");

            migrationBuilder.DropColumn(
                name: "LockTimeoutMinutes",
                table: "Settings");

            migrationBuilder.DropColumn(
                name: "MaxLoginAttempts",
                table: "Settings");
        }
    }
}
