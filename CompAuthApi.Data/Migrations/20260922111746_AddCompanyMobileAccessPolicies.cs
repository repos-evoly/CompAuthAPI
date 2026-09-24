using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompAuthApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCompanyMobileAccessPolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CompanyMobileAccessPolicies",
                columns: table => new
                {
                    CompanyCode = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    RequireApprovedDevice = table.Column<bool>(type: "bit", nullable: false),
                    PolicyVersion = table.Column<int>(type: "int", nullable: false),
                    UpdatedByAuthUserId = table.Column<int>(type: "int", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CompanyMobileAccessPolicies", x => x.CompanyCode);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CompanyMobileAccessPolicies");
        }
    }
}
