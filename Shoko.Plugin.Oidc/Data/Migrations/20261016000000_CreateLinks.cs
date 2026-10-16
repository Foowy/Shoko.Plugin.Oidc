using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Shoko.Plugin.Oidc.Data.Migrations;

[DbContext(typeof(OidcDbContext))]
[Migration("20261016000000_CreateLinks")]
public class CreateLinks : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "Links",
            columns: table => new
            {
                ID = table.Column<int>(type: "INTEGER", nullable: false).Annotation("Sqlite:Autoincrement", true),
                Authority = table.Column<string>(type: "TEXT", nullable: false),
                Subject = table.Column<string>(type: "TEXT", nullable: false),
                UserID = table.Column<int>(type: "INTEGER", nullable: false),
            },
            constraints: table => table.PrimaryKey("PK_Links", x => x.ID));

        migrationBuilder.CreateIndex(name: "IX_Links_Authority_Subject", table: "Links", columns: ["Authority", "Subject"], unique: true);
        migrationBuilder.CreateIndex(name: "IX_Links_Authority_UserID", table: "Links", columns: ["Authority", "UserID"], unique: true);
    }
}
