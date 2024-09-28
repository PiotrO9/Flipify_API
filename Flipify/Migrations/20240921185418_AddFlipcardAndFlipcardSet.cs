using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Flipify.Migrations
{
    /// <inheritdoc />
    public partial class AddFlipcardAndFlipcardSet : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Flipcards",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FlipcardSetId = table.Column<Guid>(type: "uuid", nullable: false),
                    NativeWord = table.Column<string>(type: "text", nullable: false),
                    ForeignWord = table.Column<string>(type: "text", nullable: false),
                    NativeWordExample = table.Column<string>(type: "text", nullable: false),
                    ForeignWordExample = table.Column<string>(type: "text", nullable: false),
                    LastReviewDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NextReviewDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IntervalDays = table.Column<int>(type: "integer", nullable: false),
                    Ef = table.Column<decimal>(type: "numeric", nullable: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Flipcards", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Flipcards_FlipcardSets_FlipcardSetId",
                        column: x => x.FlipcardSetId,
                        principalTable: "FlipcardSets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Flipcards_FlipcardSetId",
                table: "Flipcards",
                column: "FlipcardSetId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Flipcards");
        }
    }
}
