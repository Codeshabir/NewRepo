using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Kind_Heart_Charity.Migrations
{
    /// <inheritdoc />
    public partial class AddPagePost : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PageTitle",
                table: "DynamicPages");

            migrationBuilder.CreateTable(
                name: "PagePosts",
                columns: table => new
                {
                    ID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DynamicPageID = table.Column<int>(type: "int", nullable: false),
                    PostTitle = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PostDescription = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PostThumbnail = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PagePosts", x => x.ID);
                    table.ForeignKey(
                        name: "FK_PagePosts_DynamicPages_DynamicPageID",
                        column: x => x.DynamicPageID,
                        principalTable: "DynamicPages",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PagePosts_DynamicPageID",
                table: "PagePosts",
                column: "DynamicPageID");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PagePosts");

            migrationBuilder.AddColumn<string>(
                name: "PageTitle",
                table: "DynamicPages",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }
    }
}
