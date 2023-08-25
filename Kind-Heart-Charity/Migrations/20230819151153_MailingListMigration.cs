using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Kind_Heart_Charity.Migrations
{
    /// <inheritdoc />
    public partial class MailingListMigration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "068f97bc-b03b-47a8-8da7-5871d9fd0f92");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "725c5c3b-fcf5-4070-9728-aff07211b4de");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "e1057eff-0243-4fb3-8a64-9fe3ef8814bf");

            migrationBuilder.CreateTable(
                name: "MailingLists",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Email = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedDate = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MailingLists", x => x.Id);
                });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "12caa7b9-63fd-4186-bd89-ebc1d12ce43f", "2", "User", "User" },
                    { "d172d6e9-a1ed-4019-9603-84e8ff65b4c8", "3", "HR", "HR" },
                    { "dfa0c2d0-c600-416d-a911-0633c302c8ee", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MailingLists");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "12caa7b9-63fd-4186-bd89-ebc1d12ce43f");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "d172d6e9-a1ed-4019-9603-84e8ff65b4c8");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "dfa0c2d0-c600-416d-a911-0633c302c8ee");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "068f97bc-b03b-47a8-8da7-5871d9fd0f92", "1", "Admin", "Admin" },
                    { "725c5c3b-fcf5-4070-9728-aff07211b4de", "2", "User", "User" },
                    { "e1057eff-0243-4fb3-8a64-9fe3ef8814bf", "3", "HR", "HR" }
                });
        }
    }
}
