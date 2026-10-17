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

public sealed class OidcAdminGroupTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private readonly Mock<IUserService> _users = new();
    private readonly OidcUserResolver _resolver;
    private static readonly OidcConfiguration Config = new() { AdminGroup = "shoko-admins" };

    public OidcAdminGroupTests()
    {
        _connection.Open();
        using (var db = NewContext())
        {
            db.Database.Migrate();
            db.Links.Add(new OidcLink { Authority = "https://sso.example", Subject = "sub-1", UserID = 5 });
            db.SaveChanges();
        }

        var factory = new Mock<IDbContextFactory<OidcDbContext>>();
        factory.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => NewContext());
        _resolver = new OidcUserResolver(factory.Object, _users.Object);
        _users.Setup(u => u.UpdateUser(It.IsAny<IUser>(), It.IsAny<UserUpdate>())).ReturnsAsync((IUser u, UserUpdate _) => u);
    }

    public void Dispose() => _connection.Dispose();

    private OidcDbContext NewContext()
        => new(new DbContextOptionsBuilder<OidcDbContext>().UseSqlite(_connection).Options);

    private static IUser User(int id, bool admin)
    {
        var user = new Mock<IUser>();
        user.SetupGet(u => u.LocalID).Returns(id);
        user.SetupGet(u => u.IsAdmin).Returns(admin);
        return user.Object;
    }

    private Task<IUser> SignIn(IUser linked, JsonNode? groups, OidcConfiguration? config = null, params IUser[] others)
    {
        _users.Setup(u => u.GetUserByID(5)).Returns(linked);
        _users.Setup(u => u.GetUsers()).Returns([linked, .. others]);
        var claims = new JsonObject { ["sub"] = "sub-1" };
        if (groups is not null)
            claims["groups"] = groups;
        return _resolver.ResolveAsync(new OidcIdentity("https://sso.example", "sub-1", claims), config ?? Config, CancellationToken.None);
    }

    private void VerifyAdminSet(bool? expected)
        => _users.Verify(u => u.UpdateUser(It.IsAny<IUser>(), It.Is<UserUpdate>(x => x.IsAdmin == expected)), expected is null ? Times.Never : Times.Once);

    [Fact]
    public async Task AMemberOfTheGroup_IsPromoted()
    {
        await SignIn(User(5, false), new JsonArray("users", "shoko-admins"));
        VerifyAdminSet(true);
    }

    [Fact]
    public async Task ANonMemberAdmin_IsDemotedWhenAnotherAdminExists()
    {
        await SignIn(User(5, true), new JsonArray("users"), others: User(6, true));
        VerifyAdminSet(false);
    }

    [Fact]
    public async Task TheLastAdmin_IsNeverDemoted()
    {
        await SignIn(User(5, true), new JsonArray("users"), others: User(6, false));
        VerifyAdminSet(null);
    }

    [Fact]
    public async Task AMissingGroupsClaim_ChangesNothing()
    {
        await SignIn(User(5, true), null, others: User(6, true));
        VerifyAdminSet(null);
    }

    [Fact]
    public async Task ABlankAdminGroup_ChangesNothing()
    {
        await SignIn(User(5, false), new JsonArray("shoko-admins"), new OidcConfiguration());
        VerifyAdminSet(null);
    }

    [Fact]
    public async Task ASpaceSeparatedStringClaim_IsAccepted()
    {
        await SignIn(User(5, false), JsonValue.Create("users shoko-admins"));
        VerifyAdminSet(true);
    }

    [Fact]
    public async Task ARolesObject_MatchesOnItsKeys()
    {
        await SignIn(User(5, false), new JsonObject { ["shoko-admins"] = new JsonObject { ["org-1"] = "example.test" } });
        VerifyAdminSet(true);
    }

    [Fact]
    public async Task APartialGroupName_DoesNotMatch()
    {
        await SignIn(User(5, false), new JsonArray("shoko-admins-extra"));
        VerifyAdminSet(null);
    }
}
