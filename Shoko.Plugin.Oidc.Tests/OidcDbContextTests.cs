using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Shoko.Plugin.Oidc.Data;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public sealed class OidcDbContextTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public OidcDbContextTests() => _connection.Open();

    public void Dispose() => _connection.Dispose();

    private OidcDbContext CreateMigrated()
    {
        var context = new OidcDbContext(new DbContextOptionsBuilder<OidcDbContext>().UseSqlite(_connection).Options);
        context.Database.Migrate();
        return context;
    }

    [Fact]
    public void Migrations_MatchTheModel()
    {
        using var context = CreateMigrated();
        Assert.False(context.Database.HasPendingModelChanges());
    }

    [Fact]
    public void ASubjectCanOnlyBeLinkedOncePerAuthority()
    {
        using var context = CreateMigrated();
        context.Links.Add(new OidcLink { Authority = "https://a", Subject = "s1", UserID = 1 });
        context.SaveChanges();

        context.Links.Add(new OidcLink { Authority = "https://a", Subject = "s1", UserID = 2 });
        Assert.Throws<DbUpdateException>(() => context.SaveChanges());
    }

    [Fact]
    public void AUserCanOnlyBeLinkedOncePerAuthority_ButSameSubjectIsFineOnAnotherAuthority()
    {
        using var context = CreateMigrated();
        context.Links.Add(new OidcLink { Authority = "https://a", Subject = "s1", UserID = 1 });
        context.Links.Add(new OidcLink { Authority = "https://b", Subject = "s1", UserID = 1 });
        context.SaveChanges();

        context.Links.Add(new OidcLink { Authority = "https://a", Subject = "s2", UserID = 1 });
        Assert.Throws<DbUpdateException>(() => context.SaveChanges());
    }
}
