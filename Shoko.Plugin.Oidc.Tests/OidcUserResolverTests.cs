using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Moq;
using Shoko.Abstractions.User;
using Shoko.Abstractions.User.Services;
using Shoko.Abstractions.User.Update;
using Shoko.Plugin.Oidc.Config;
using Shoko.Plugin.Oidc.Data;
using Shoko.Plugin.Oidc.Flow;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public sealed class OidcUserResolverTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    private readonly Mock<IUserService> _users = new();

    private readonly OidcUserResolver _resolver;

    public OidcUserResolverTests()
    {
        _connection.Open();
        using (var db = NewContext())
            db.Database.Migrate();
        var factory = new Mock<IDbContextFactory<OidcDbContext>>();
        factory.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => NewContext());
        _resolver = new OidcUserResolver(factory.Object, _users.Object);
    }

    public void Dispose() => _connection.Dispose();

    private OidcDbContext NewContext()
        => new(new DbContextOptionsBuilder<OidcDbContext>().UseSqlite(_connection).Options);

    private static Mock<IUser> User(int id, string name)
    {
        var user = new Mock<IUser>();
        user.SetupGet(u => u.LocalID).Returns(id);
        user.SetupGet(u => u.Username).Returns(name);
        return user;
    }

    private static OidcIdentity Identity(string subject = "sub-1", string username = "alice")
        => new("https://sso.example", subject, new JsonObject { ["sub"] = subject, ["preferred_username"] = username });

    [Fact]
    public async Task ALinkedSubject_SignsInAsItsUser()
    {
        using (var db = NewContext())
        {
            db.Links.Add(new OidcLink { Authority = "https://sso.example", Subject = "sub-1", UserID = 5 });
            db.SaveChanges();
        }

        _users.Setup(u => u.GetUserByID(5)).Returns(User(5, "linked").Object);

        var user = await _resolver.ResolveAsync(Identity(), new OidcConfiguration(), CancellationToken.None);

        Assert.Equal(5, user.LocalID);
    }

    [Fact]
    public async Task AnUnlinkedSubject_IsRejectedWhenCreatingUsersIsOff()
    {
        var ex = await Assert.ThrowsAsync<OidcException>(() => _resolver.ResolveAsync(Identity(), new OidcConfiguration(), CancellationToken.None));

        Assert.Equal("not_linked", ex.Code);
        _users.Verify(u => u.CreateUser(It.IsAny<UserUpdate>()), Times.Never);
    }

    [Fact]
    public async Task AnExistingAccountWithTheSameUsername_IsNeverLinkedByName()
    {
        _users.Setup(u => u.GetUserByUsername("alice")).Returns(User(1, "alice").Object);

        var ex = await Assert.ThrowsAsync<OidcException>(() =>
            _resolver.ResolveAsync(Identity(), new OidcConfiguration { AutoCreateUsers = true }, CancellationToken.None));

        Assert.Equal("username_taken", ex.Code);
        using var db = NewContext();
        Assert.Empty(db.Links);
        _users.Verify(u => u.CreateUser(It.IsAny<UserUpdate>()), Times.Never);
    }

    [Fact]
    public async Task CreatingUsersOn_CreatesANonAdminAccountWithARandomPasswordAndLinksIt()
    {
        UserUpdate? sent = null;
        _users.Setup(u => u.CreateUser(It.IsAny<UserUpdate>()))
            .Callback<UserUpdate>(update => sent = update)
            .ReturnsAsync(User(9, "alice").Object);

        var user = await _resolver.ResolveAsync(Identity(), new OidcConfiguration { AutoCreateUsers = true }, CancellationToken.None);

        Assert.Equal(9, user.LocalID);
        Assert.Equal("alice", sent!.Username);
        Assert.False(sent.IsAdmin);
        Assert.Equal(64, sent.Password!.Length);
        using var db = NewContext();
        var link = Assert.Single(db.Links);
        Assert.Equal((9, "sub-1", "https://sso.example"), (link.UserID, link.Subject, link.Authority));
    }

    [Fact]
    public async Task ALostLinkRace_DeletesTheCreatedAccountAndUsesTheWinner()
    {
        var loser = User(10, "alice");
        _users.Setup(u => u.CreateUser(It.IsAny<UserUpdate>()))
            .Callback<UserUpdate>(_ =>
            {
                using var db = NewContext();
                db.Links.Add(new OidcLink { Authority = "https://sso.example", Subject = "sub-1", UserID = 4 });
                db.SaveChanges();
            })
            .ReturnsAsync(loser.Object);
        _users.Setup(u => u.GetUserByID(4)).Returns(User(4, "winner").Object);

        var user = await _resolver.ResolveAsync(Identity(), new OidcConfiguration { AutoCreateUsers = true }, CancellationToken.None);

        Assert.Equal(4, user.LocalID);
        _users.Verify(u => u.DeleteUser(loser.Object), Times.Once);
    }

    [Fact]
    public void Username_FallsBackToEmailThenSubject()
    {
        var emailOnly = new OidcIdentity("i", "s", new JsonObject { ["sub"] = "s", ["email"] = "a@b.c" });
        var nothing = new OidcIdentity("i", "s", new JsonObject { ["sub"] = "s" });
        var custom = new OidcIdentity("i", "s", new JsonObject { ["sub"] = "s", ["nickname"] = "nick", ["preferred_username"] = "pu" });

        Assert.Equal("a@b.c", emailOnly.GetUsername("preferred_username"));
        Assert.Equal("s", nothing.GetUsername("preferred_username"));
        Assert.Equal("nick", custom.GetUsername("nickname"));
    }
}
