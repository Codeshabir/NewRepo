﻿using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Kind_Heart_Charity.Migrations
{
    /// <inheritdoc />
    public partial class DeleteTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PageContent");

            migrationBuilder.DropTable(
                name: "PageGalleryItems");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PageContent",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DynamicPagesId = table.Column<int>(type: "int", nullable: false),
                    ContentDescription = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ContentTitle = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DynamicPageID = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PageContent", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PageContent_DynamicPages_DynamicPagesId",
                        column: x => x.DynamicPagesId,
                        principalTable: "DynamicPages",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PageGalleryItems",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DynamicPagesId = table.Column<int>(type: "int", nullable: false),
                    DynamicPageID = table.Column<int>(type: "int", nullable: false),
                    GalleryPath = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PageGalleryItems", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PageGalleryItems_DynamicPages_DynamicPagesId",
                        column: x => x.DynamicPagesId,
                        principalTable: "DynamicPages",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PageContent_DynamicPagesId",
                table: "PageContent",
                column: "DynamicPagesId");

            migrationBuilder.CreateIndex(
                name: "IX_PageGalleryItems_DynamicPagesId",
                table: "PageGalleryItems",
                column: "DynamicPagesId");
        }
    }
}
