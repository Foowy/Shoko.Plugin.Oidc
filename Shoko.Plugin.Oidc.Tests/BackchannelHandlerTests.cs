using Shoko.Plugin.Oidc.Config;
using Shoko.Plugin.Oidc.Flow;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public class BackchannelHandlerTests
{
    private sealed class Capture : HttpMessageHandler
    {
        public HttpRequestMessage? Seen { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Seen = request;
            return Task.FromResult(new HttpResponseMessage());
        }
    }

    private static async Task<HttpRequestMessage> Send(OidcConfiguration config, string url)
    {
        var inner = new Capture();
        using var client = new HttpClient(new BackchannelHandler(() => config) { InnerHandler = inner });
        await client.GetAsync(url, TestContext.Current.CancellationToken);
        return inner.Seen!;
    }

    private static OidcConfiguration Config(string? backchannel, bool insecure = true)
        => new() { Authority = "https://sso.example.com/application/o/shoko/", BackchannelUrl = backchannel, AllowInsecureHttp = insecure };

    [Fact]
    public async Task ARequestToTheAuthorityHost_GoesToTheBackchannelWithTheOriginalHostHeader()
    {
        var seen = await Send(Config("http://authentik:9000"), "https://sso.example.com/application/o/token/?a=1");

        Assert.Equal("http://authentik:9000/application/o/token/?a=1", seen.RequestUri!.AbsoluteUri);
        Assert.Equal("sso.example.com", seen.Headers.Host);
        Assert.Equal("https", Assert.Single(seen.Headers.GetValues("X-Forwarded-Proto")));
    }

    [Fact]
    public async Task AUrlTheProviderAdvertisedAsPlainHttp_IsStillRerouted()
    {
        var seen = await Send(Config("http://authentik:9000"), "http://sso.example.com/application/o/shoko/jwks/");

        Assert.Equal("http://authentik:9000/application/o/shoko/jwks/", seen.RequestUri!.AbsoluteUri);
        Assert.Equal("sso.example.com", seen.Headers.Host);
    }

    [Fact]
    public async Task ARequestToAnotherHost_IsLeftAlone()
    {
        var seen = await Send(Config("http://authentik:9000"), "https://other.example.com/jwks");

        Assert.Equal("https://other.example.com/jwks", seen.RequestUri!.AbsoluteUri);
        Assert.Null(seen.Headers.Host);
    }

    [Fact]
    public async Task WithoutABackchannel_NothingChanges()
    {
        var seen = await Send(Config(null), "https://sso.example.com/x");

        Assert.Equal("https://sso.example.com/x", seen.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task ANonDefaultAuthorityPort_IsKeptInTheHostHeader()
    {
        var config = new OidcConfiguration { Authority = "https://sso.example.com:8443/", BackchannelUrl = "https://10.0.0.5:9443" };

        var seen = await Send(config, "https://sso.example.com:8443/token");

        Assert.Equal("sso.example.com:8443", seen.Headers.Host);
        Assert.Equal("https://10.0.0.5:9443/token", seen.RequestUri!.AbsoluteUri);
    }

    [Theory]
    [InlineData("not a url")]
    [InlineData("ftp://authentik:21")]
    public async Task AnInvalidBackchannel_FailsTheRequest(string backchannel)
        => await Assert.ThrowsAsync<HttpRequestException>(() => Send(Config(backchannel), "https://sso.example.com/x"));

    [Fact]
    public async Task PlainHttpBackchannel_NeedsAllowInsecureHttp()
        => await Assert.ThrowsAsync<HttpRequestException>(() => Send(Config("http://authentik:9000", insecure: false), "https://sso.example.com/x"));
}
