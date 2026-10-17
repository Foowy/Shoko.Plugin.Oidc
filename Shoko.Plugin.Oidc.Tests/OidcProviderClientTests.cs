using Microsoft.Extensions.Logging;
using Moq;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;
using Shoko.Plugin.Oidc.Config;
using Shoko.Plugin.Oidc.Flow;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public class OidcProviderClientTests
{
    private const string Redirect = "https://shoko.example/api/plugin/Oidc/callback";

    private static OidcConfiguration Config(MockProvider provider, Action<OidcConfiguration>? tweak = null)
    {
        var config = new OidcConfiguration
        {
            Authority = provider.Authority,
            ClientId = MockProvider.ClientId,
            ClientSecret = MockProvider.ClientSecret,
            AllowInsecureHttp = true,
        };
        tweak?.Invoke(config);
        return config;
    }

    private static JsonObject Claims(string subject = "user-1", string? username = "alice")
    {
        var claims = new JsonObject { ["sub"] = subject };
        if (username is not null)
            claims["preferred_username"] = username;
        return claims;
    }

    private static async Task<(OidcProviderClient Client, string Code, PendingLogin Pending)> Start(
        MockProvider provider, OidcConfiguration config, JsonObject idClaims, JsonObject? userInfo = null, string? nonceAtProvider = null,
        HttpMessageHandler? handler = null, ILogger? logger = null)
    {
        var client = new OidcProviderClient(handler is null ? new HttpClient() : new HttpClient(handler), () => config, logger);
        var verifier = OidcFlowStore.RandomToken();
        var nonce = OidcFlowStore.RandomToken();
        var url = await client.BuildAuthorizeUrlAsync(Redirect, "state-1", nonce, verifier, CancellationToken.None);
        var query = QueryHelpers.ParseQuery(url.Query);
        var code = provider.IssueCode(Redirect, query["code_challenge"]!, nonceAtProvider ?? nonce, idClaims, userInfo);
        return (client, code, new PendingLogin(nonce, verifier, "/webui", Redirect, DateTimeOffset.UtcNow.AddMinutes(5)));
    }

    private static async Task<OidcIdentity> Run(MockProvider provider, OidcConfiguration config, JsonObject idClaims, JsonObject? userInfo = null)
    {
        var (client, code, pending) = await Start(provider, config, idClaims, userInfo);
        return await client.CompleteAsync(code, pending, CancellationToken.None);
    }

    [Fact]
    public async Task AuthorizeUrl_CarriesPkceStateNonceAndScopes()
    {
        await using var provider = new MockProvider();
        var client = new OidcProviderClient(new HttpClient(), () => Config(provider, c => c.Scopes = "profile groups"));

        var url = await client.BuildAuthorizeUrlAsync(Redirect, "st", "nn", "verifier", CancellationToken.None);
        var query = QueryHelpers.ParseQuery(url.Query);

        Assert.Equal("code", query["response_type"]);
        Assert.Equal(MockProvider.ClientId, query["client_id"]);
        Assert.Equal(Redirect, query["redirect_uri"]);
        Assert.Equal("openid profile groups", query["scope"]);
        Assert.Equal("st", query["state"]);
        Assert.Equal("nn", query["nonce"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal(OidcFlowStore.ChallengeFor("verifier"), query["code_challenge"]);
    }

    [Fact]
    public async Task HappyPath_Rs256_ReturnsTheIssuerSubjectAndUsername()
    {
        await using var provider = new MockProvider();

        var identity = await Run(provider, Config(provider), Claims());

        Assert.Equal(provider.Issuer, identity.Issuer);
        Assert.Equal("user-1", identity.Subject);
        Assert.Equal("alice", identity.GetUsername("preferred_username"));
    }

    [Fact]
    public async Task Es256Signing_IsAccepted()
    {
        await using var provider = new MockProvider(useEcdsa: true);

        var identity = await Run(provider, Config(provider), Claims());

        Assert.Equal("user-1", identity.Subject);
    }

    [Fact]
    public async Task IssuerWithTrailingSlashAndPerClientPath_WorkWithAnAuthorityOrAFullDiscoveryUrl()
    {
        await using var provider = new MockProvider(pathPrefix: "/application/o/shoko", trailingSlashIssuer: true);

        var byAuthority = await Run(provider, Config(provider), Claims());
        var byDiscoveryUrl = await Run(provider, Config(provider, c => c.Authority = provider.Origin + "/application/o/shoko/.well-known/openid-configuration"), Claims());

        Assert.Equal(provider.Issuer, byAuthority.Issuer);
        Assert.Equal(provider.Issuer, byDiscoveryUrl.Issuer);
    }

    [Fact]
    public async Task ClaimsOnlyAtUserinfo_AreMergedAndSubjectIsChecked()
    {
        await using var provider = new MockProvider();
        var userInfo = new JsonObject { ["sub"] = "user-1", ["preferred_username"] = "from-userinfo", ["groups"] = new JsonArray("a") };

        var identity = await Run(provider, Config(provider), Claims(username: null), userInfo);

        Assert.Equal("from-userinfo", identity.GetUsername("preferred_username"));
        Assert.NotNull(identity.Claims["groups"]);
    }

    [Fact]
    public async Task UserinfoWithAnotherSubject_IsRejected()
    {
        await using var provider = new MockProvider();
        var userInfo = new JsonObject { ["sub"] = "someone-else" };

        var ex = await Assert.ThrowsAsync<OidcException>(() => Run(provider, Config(provider), Claims(), userInfo));

        Assert.Equal("subject_mismatch", ex.Code);
    }

    [Fact]
    public async Task ProviderWithoutUserinfoEndpoint_StillSignsIn()
    {
        await using var provider = new MockProvider(omitUserInfo: true);

        var identity = await Run(provider, Config(provider), Claims());

        Assert.Equal("user-1", identity.Subject);
    }

    [Theory]
    [InlineData("client_secret_basic")]
    [InlineData("client_secret_post")]
    public async Task Auto_FollowsWhatTheProviderAdvertises(string method)
    {
        await using var provider = new MockProvider(authMethods: [method]);

        var identity = await Run(provider, Config(provider), Claims());

        Assert.Equal("user-1", identity.Subject);
    }

    [Fact]
    public async Task Auto_UsesBasicWhenTheProviderAdvertisesNothing()
    {
        await using var provider = new MockProvider(omitAuthMethods: true);

        Assert.Equal("user-1", (await Run(provider, Config(provider), Claims())).Subject);
    }

    [Fact]
    public async Task AWrongPostSecret_IsRejectedByTheProvider()
    {
        await using var provider = new MockProvider(authMethods: ["client_secret_post"]);

        var ex = await Assert.ThrowsAsync<OidcException>(() => Run(provider, Config(provider, c => c.ClientSecret = "wrong"), Claims()));

        Assert.Equal("token_failed", ex.Code);
    }

    [Fact]
    public async Task AWrongPkceVerifier_IsRejectedByTheProvider()
    {
        await using var provider = new MockProvider();
        var (client, code, pending) = await Start(provider, Config(provider), Claims());

        var ex = await Assert.ThrowsAsync<OidcException>(() => client.CompleteAsync(code, pending with { CodeVerifier = "another-verifier" }, CancellationToken.None));

        Assert.Equal("token_failed", ex.Code);
    }

    [Fact]
    public async Task ANonceThatDoesNotMatch_IsRejected()
    {
        await using var provider = new MockProvider();
        var (client, code, pending) = await Start(provider, Config(provider), Claims(), nonceAtProvider: "replayed-nonce");

        var ex = await Assert.ThrowsAsync<OidcException>(() => client.CompleteAsync(code, pending, CancellationToken.None));

        Assert.Equal("nonce_mismatch", ex.Code);
    }

    [Fact]
    public async Task ATokenForAnotherAudience_IsRejected()
    {
        await using var provider = new MockProvider { Audience = "someone-else" };

        var ex = await Assert.ThrowsAsync<OidcException>(() => Run(provider, Config(provider), Claims()));

        Assert.Equal("invalid_id_token", ex.Code);
    }

    [Fact]
    public async Task ARotatedProviderKey_IsPickedUpOnTheNextSignIn()
    {
        await using var provider = new MockProvider();
        var config = Config(provider);
        var (client, code, pending) = await Start(provider, config, Claims());
        await client.BuildAuthorizeUrlAsync(Redirect, "s", "n", "v", CancellationToken.None);
        provider.RotateSigningKey();

        var identity = await client.CompleteAsync(code, pending, CancellationToken.None);

        Assert.False(string.IsNullOrEmpty(identity.Subject));
    }

    [Fact]
    public async Task PlainHttp_IsRefusedUnlessAllowed()
    {
        await using var provider = new MockProvider();
        var client = new OidcProviderClient(new HttpClient(), () => Config(provider, c => c.AllowInsecureHttp = false));

        var ex = await Assert.ThrowsAsync<OidcException>(() => client.BuildAuthorizeUrlAsync(Redirect, "s", "n", "v", CancellationToken.None));

        Assert.Equal("discovery_failed", ex.Code);
    }

    [Fact]
    public async Task AnUnconfiguredPlugin_FailsWithNotConfigured()
    {
        var client = new OidcProviderClient(new HttpClient(), () => new OidcConfiguration());

        var ex = await Assert.ThrowsAsync<OidcException>(() => client.BuildAuthorizeUrlAsync(Redirect, "s", "n", "v", CancellationToken.None));

        Assert.Equal("not_configured", ex.Code);
    }

    [Theory]
    [InlineData("https://sso.example", "https://sso.example/.well-known/openid-configuration")]
    [InlineData("https://sso.example/", "https://sso.example/.well-known/openid-configuration")]
    [InlineData("https://sso.example/realms/x", "https://sso.example/realms/x/.well-known/openid-configuration")]
    [InlineData("https://sso.example/oauth2/openid/shoko/.well-known/openid-configuration", "https://sso.example/oauth2/openid/shoko/.well-known/openid-configuration")]
    public void DiscoveryAddress_AcceptsAnIssuerOrTheFullUrl(string authority, string expected)
        => Assert.Equal(expected, OidcProviderClient.DiscoveryAddress(authority));

    [Theory]
    [InlineData("s", new string[0], OidcTokenAuthMethod.ClientSecretBasic)]
    [InlineData("s", new[] { "client_secret_post" }, OidcTokenAuthMethod.ClientSecretPost)]
    [InlineData("s", new[] { "client_secret_post", "client_secret_basic" }, OidcTokenAuthMethod.ClientSecretBasic)]
    [InlineData("", new[] { "client_secret_basic" }, OidcTokenAuthMethod.None)]
    public void AuthMethod_Auto_PrefersBasicAndFallsBackToPost(string secret, string[] advertised, OidcTokenAuthMethod expected)
        => Assert.Equal(expected, OidcProviderClient.ResolveAuthMethod(new OidcConfiguration { ClientSecret = secret }, advertised));

    [Fact]
    public void AuthMethod_AnExplicitChoiceWins()
        => Assert.Equal(OidcTokenAuthMethod.ClientSecretPost,
            OidcProviderClient.ResolveAuthMethod(new OidcConfiguration { ClientSecret = "s", TokenAuthMethod = OidcTokenAuthMethod.ClientSecretPost }, ["client_secret_basic"]));

    private sealed class FailingUserInfo : DelegatingHandler
    {
        public FailingUserInfo() : base(new HttpClientHandler()) { }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => request.RequestUri!.AbsolutePath.EndsWith("/userinfo", StringComparison.Ordinal)
                ? new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError)
                : await base.SendAsync(request, cancellationToken);
    }

    [Fact]
    public async Task ANonStringUserInfoSubject_FailsAsAMismatchInsteadOfThrowing()
    {
        await using var provider = new MockProvider();

        var ex = await Assert.ThrowsAsync<OidcException>(() =>
            Run(provider, Config(provider), Claims(), new JsonObject { ["sub"] = 12345 }));

        Assert.Equal("subject_mismatch", ex.Code);
    }

    [Fact]
    public async Task AFailingUserInfoEndpoint_IsLoggedAndTheSignInStillWorks()
    {
        await using var provider = new MockProvider();
        var logger = new Mock<ILogger>();
        var (client, code, pending) = await Start(provider, Config(provider), Claims(), new JsonObject { ["sub"] = "user-1" }, handler: new FailingUserInfo(), logger: logger.Object);

        var identity = await client.CompleteAsync(code, pending, CancellationToken.None);

        Assert.Equal("user-1", identity.Subject);
        logger.Verify(l => l.Log(LogLevel.Warning, It.IsAny<EventId>(), It.IsAny<It.IsAnyType>(), null, It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once);
    }
}
