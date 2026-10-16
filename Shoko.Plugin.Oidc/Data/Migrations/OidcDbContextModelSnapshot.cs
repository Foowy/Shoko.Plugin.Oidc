using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Shoko.Plugin.Oidc.Data.Migrations;

[DbContext(typeof(OidcDbContext))]
public class OidcDbContextModelSnapshot : ModelSnapshot
{
    protected override void BuildModel(ModelBuilder modelBuilder)
    {
        modelBuilder.HasAnnotation("ProductVersion", "10.0.12");

        modelBuilder.Entity<OidcLink>(b =>
        {
            b.Property<int>("ID").ValueGeneratedOnAdd().HasColumnType("INTEGER");
            b.Property<string>("Authority").IsRequired().HasColumnType("TEXT");
            b.Property<string>("Subject").IsRequired().HasColumnType("TEXT");
            b.Property<int>("UserID").HasColumnType("INTEGER");
            b.HasKey("ID");
            b.HasIndex("Authority", "Subject").IsUnique();
            b.HasIndex("Authority", "UserID").IsUnique();
            b.ToTable("Links");
        });
    }
}
