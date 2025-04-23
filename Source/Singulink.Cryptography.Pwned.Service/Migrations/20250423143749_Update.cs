using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Singulink.Cryptography.Pwned.Service.Migrations;

/// <inheritdoc />
public partial class Update : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AlterColumn<string>(
            name: "Hash",
            table: "Passwords",
            type: "char(40)",
            nullable: false,
            oldClrType: typeof(string),
            oldType: "char(40)",
            oldCollation: "Latin1_General_CI_AS");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AlterColumn<string>(
            name: "Hash",
            table: "Passwords",
            type: "char(40)",
            nullable: false,
            collation: "Latin1_General_CI_AS",
            oldClrType: typeof(string),
            oldType: "char(40)");
    }
}
