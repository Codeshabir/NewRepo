using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Kind_Heart_Charity.Migrations
{
    /// <inheritdoc />
    public partial class RolesSeeded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
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

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
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
        }
    }
}
