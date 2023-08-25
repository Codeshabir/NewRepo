using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Kind_Heart_Charity.Migrations
{
    /// <inheritdoc />
    public partial class addedDynamicPages3 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SectionName",
                table: "DynamicPages",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SectionName",
                table: "DynamicPages");
        }
    }
}
