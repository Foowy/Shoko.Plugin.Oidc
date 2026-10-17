using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Shoko.Abstractions.Config.Services;
using Shoko.Abstractions.User;
using Shoko.Abstractions.User.Services;
using Shoko.Plugin.Oidc.Config;
using Shoko.Plugin.Oidc.Controllers;
using Shoko.Plugin.Oidc.Data;
using Shoko.Plugin.Oidc.Flow;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public sealed class OidcLinkFlowTests : IDisposable
{
    private const string BaseUrl = "https://shoko.example";

    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    private readonly Mock<IUserService> _users = new();

    private readonly OidcFlowStore _store = new();

    public OidcLinkFlowTests()
    {
        _connection.Open();
        using var db = NewContext();
        db.Database.Migrate();
    }

    public void Dispose() => _connection.Dispose();

    private OidcDbContext NewContext()
        => new(new DbContextOptionsBuilder<OidcDbContext>().UseSqlite(_connection).Options);

    private OidcController NewController(OidcConfiguration config, string? stateCookie = null)
    {
        var configService = new Mock<IConfigurationService>();
        configService.Setup(c => c.Load<OidcConfiguration>(It.IsAny<bool>())).Returns(config);
        var factory = new Mock<IDbContextFactory<OidcDbContext>>();
        factory.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => NewContext());
        var http = new DefaultHttpContext();
        if (stateCookie is not null)
            http.Request.Headers.Cookie = $"shoko_oidc_state={stateCookie}";
        return new OidcController(
            configService.Object,
            new OidcProviderClient(new HttpClient(), () => config),
            _store,
            new OidcUserResolver(factory.Object, _users.Object),
            _users.Object,
            new Mock<IAuthenticationThrottleService>().Object,
            NullLogger<OidcController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
            Url = new Mock<IUrlHelper>().Object,
        };
    }

    private static OidcConfiguration Config(MockProvider provider) => new()
    {
        Authority = provider.Authority,
        ClientId = MockProvider.ClientId,
        ClientSecret = MockProvider.ClientSecret,
        AllowInsecureHttp = true,
        PublicBaseUrl = BaseUrl,
    };

    private async Task<ContentResult> LinkThroughTheProvider(MockProvider provider, int userId, string subject)
    {
        var config = Config(provider);
        var ticket = _store.AddLinkTicket(userId);
        var login = Assert.IsType<RedirectResult>(await NewController(config).Login(null, ticket, CancellationToken.None));
        var query = QueryHelpers.ParseQuery(new Uri(login.Url).Query);
        var state = query["state"].ToString();
        var code = provider.IssueCode(query["redirect_uri"]!, query["code_challenge"]!, query["nonce"]!, new JsonObject { ["sub"] = subject });

        return Assert.IsType<ContentResult>(await NewController(config, stateCookie: state).Callback(code, state, null, CancellationToken.None));
    }

    [Fact]
    public async Task LinkingThroughTheProvider_StoresTheLinkAndDoesNotSignIn()
    {
        await using var provider = new MockProvider();

        var page = await LinkThroughTheProvider(provider, userId: 5, subject: "sub-1");

        Assert.Contains("now linked", page.Content);
        using var db = NewContext();
        var link = Assert.Single(db.Links);
        Assert.Equal((provider.Issuer, "sub-1", 5), (link.Authority, link.Subject, link.UserID));
        Assert.Null(_store.TakeExchange("anything"));
        _users.Verify(u => u.GenerateApiTokenForUser(It.IsAny<IUser>(), It.IsAny<string>(), It.IsAny<DateTime>()), Times.Never);
    }

    [Fact]
    public async Task LinkingAnIdentityThatAnotherUserHolds_IsRefusedAndChangesNothing()
    {
        await using var provider = new MockProvider();
        await LinkThroughTheProvider(provider, userId: 5, subject: "sub-1");
        _users.Setup(u => u.GetUserByID(5)).Returns(Mock.Of<IUser>());

        var page = await LinkThroughTheProvider(provider, userId: 6, subject: "sub-1");

        Assert.Contains("subject_taken", page.Content);
        using var db = NewContext();
        Assert.Equal(5, Assert.Single(db.Links).UserID);
    }
}
