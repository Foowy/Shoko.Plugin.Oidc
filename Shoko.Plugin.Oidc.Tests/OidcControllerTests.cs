using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Shoko.Abstractions.Config.Services;
using Shoko.Abstractions.User;
using Shoko.Abstractions.User.Services;
using Shoko.Plugin.Oidc.Config;
using Shoko.Plugin.Oidc.Controllers;
using Shoko.Plugin.Oidc.Flow;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public class OidcControllerTests
{
    private readonly Mock<IUserService> _users = new();

    private readonly Mock<IAuthenticationThrottleService> _throttle = new();

    private readonly OidcFlowStore _store = new();

    private readonly OidcController _controller;

    public OidcControllerTests()
    {
        var config = new Mock<IConfigurationService>();
        config.Setup(c => c.Load<OidcConfiguration>(It.IsAny<bool>())).Returns(new OidcConfiguration { SessionHours = 2 });
        var factory = new Mock<IDbContextFactory<Data.OidcDbContext>>();
        _controller = new OidcController(
            config.Object,
            new OidcProviderClient(new HttpClient(), () => new OidcConfiguration()),
            _store,
            new OidcUserResolver(factory.Object, _users.Object),
            _users.Object,
            _throttle.Object,
            NullLogger<OidcController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
        };
    }

    private Mock<IUser> SignedInUser()
    {
        var user = new Mock<IUser>();
        user.SetupGet(u => u.LocalID).Returns(3);
        user.SetupGet(u => u.Username).Returns("alice");
        _users.Setup(u => u.GetUserByID(3)).Returns(user.Object);
        return user;
    }

    [Fact]
    public async Task Exchange_TradesAValidCodeForATokenOnce()
    {
        var user = SignedInUser();
        _users.Setup(u => u.GenerateApiTokenForUser(user.Object, "OIDC - https://sso.example - sub-1", It.IsAny<DateTime>()))
            .ReturnsAsync(new ApiToken(user.Object, "OIDC - https://sso.example - sub-1", "the-key", null));
        var code = _store.AddExchange(3, "alice", "https://sso.example", "sub-1");

        var first = Assert.IsType<ContentResult>(await _controller.Exchange(new OidcController.ExchangeRequest(code)));
        var second = await _controller.Exchange(new OidcController.ExchangeRequest(code));

        using var json = JsonDocument.Parse(first.Content!);
        Assert.Equal("the-key", json.RootElement.GetProperty("apikey").GetString());
        Assert.Equal("alice", json.RootElement.GetProperty("username").GetString());
        Assert.IsType<UnauthorizedResult>(second);
        _throttle.Verify(t => t.RegisterFailure(It.IsAny<HttpContext>()), Times.Once);
    }

    [Fact]
    public async Task Exchange_TokenLifetimeFollowsTheConfiguredSessionHours()
    {
        var user = SignedInUser();
        DateTime? expiresAt = null;
        _users.Setup(u => u.GenerateApiTokenForUser(user.Object, It.IsAny<string>(), It.IsAny<DateTime>()))
            .Callback<IUser, string, DateTime>((_, _, at) => expiresAt = at)
            .ReturnsAsync(new ApiToken(user.Object, "d", "k", null));

        await _controller.Exchange(new OidcController.ExchangeRequest(_store.AddExchange(3, "alice", "i", "s")));

        Assert.InRange(expiresAt!.Value, DateTime.Now.AddHours(2).AddMinutes(-1), DateTime.Now.AddHours(2).AddMinutes(1));
    }

    [Fact]
    public async Task Exchange_ABadCodeIsRejectedAndCountsAsAFailure()
    {
        var result = await _controller.Exchange(new OidcController.ExchangeRequest("nope"));

        Assert.IsType<UnauthorizedResult>(result);
        _throttle.Verify(t => t.RegisterFailure(It.IsAny<HttpContext>()), Times.Once);
        _users.Verify(u => u.GenerateApiTokenForUser(It.IsAny<IUser>(), It.IsAny<string>(), It.IsAny<DateTime>()), Times.Never);
    }

    [Fact]
    public async Task Exchange_ALockedOutCallerGets429WithoutSpendingTheCode()
    {
        SignedInUser();
        var code = _store.AddExchange(3, "alice", "i", "s");
        _throttle.Setup(t => t.GetRemainingLockout(It.IsAny<HttpContext>())).Returns(TimeSpan.FromMinutes(1));

        var result = await _controller.Exchange(new OidcController.ExchangeRequest(code));

        Assert.Equal(StatusCodes.Status429TooManyRequests, Assert.IsType<StatusCodeResult>(result).StatusCode);
        Assert.NotNull(_store.TakeExchange(code));
    }

    [Fact]
    public async Task Callback_AnUnknownStateEndsOnAnErrorPage()
    {
        var result = Assert.IsType<ContentResult>(await _controller.Callback("code", "forged", null, CancellationToken.None));

        Assert.Contains("invalid_state", result.Content);
        Assert.Equal("no-store", _controller.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task Callback_AValidStateFromAnotherBrowserIsRejected()
    {
        var state = _store.AddLogin("n", "v", "/webui", "https://x/callback");

        var result = Assert.IsType<ContentResult>(await _controller.Callback("code", state, null, CancellationToken.None));

        Assert.Contains("invalid_state", result.Content);
        Assert.Null(_store.TakeLogin(state));
    }
}
