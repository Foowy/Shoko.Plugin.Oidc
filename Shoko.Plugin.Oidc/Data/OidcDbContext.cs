using Microsoft.EntityFrameworkCore;

namespace Shoko.Plugin.Oidc.Data;

public class OidcDbContext(DbContextOptions<OidcDbContext> options) : DbContext(options)
{
    public DbSet<OidcLink> Links => Set<OidcLink>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<OidcLink>(e =>
        {
            e.HasIndex(l => new { l.Authority, l.Subject }).IsUnique();
            e.HasIndex(l => new { l.Authority, l.UserID }).IsUnique();
        });
    }
}
