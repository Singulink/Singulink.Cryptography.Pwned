using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Singulink.Cryptography.Pwned.Service.Migrations;

/// <inheritdoc />
public partial class InitalCreate : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "Passwords",
            columns: table => new
            {
                Hash = table.Column<string>(type: "char(40)", nullable: false, collation: "Latin1_General_CI_AS"),
                Count = table.Column<int>(type: "int", nullable: false),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Passwords", x => x.Hash);
            });
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "Passwords");
    }
}
