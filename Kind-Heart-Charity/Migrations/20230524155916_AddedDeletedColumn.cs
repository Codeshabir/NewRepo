using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Kind_Heart_Charity.Migrations
{
    /// <inheritdoc />
    public partial class AddedDeletedColumn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsDeleted",
                table: "PagePosts",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "IsDeleted",
                table: "DynamicPages",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsDeleted",
                table: "PagePosts");

            migrationBuilder.DropColumn(
                name: "IsDeleted",
                table: "DynamicPages");
        }
    }
}
