using Shoko.Plugin.Oidc.Flow;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public class OidcFlowStoreTests
{
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 16, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void ALogin_CanBeTakenOnce()
    {
        var store = new OidcFlowStore(new Clock());
        var state = store.AddLogin("n", "v", "/webui", "https://x/callback");

        Assert.Equal("n", store.TakeLogin(state)?.Nonce);
        Assert.Null(store.TakeLogin(state));
    }

    [Fact]
    public void ALogin_ExpiresAfterTenMinutes()
    {
        var clock = new Clock();
        var store = new OidcFlowStore(clock);
        var state = store.AddLogin("n", "v", "/webui", "https://x/callback");

        clock.Now += OidcFlowStore.LoginLifetime + TimeSpan.FromSeconds(1);

        Assert.Null(store.TakeLogin(state));
    }

    [Fact]
    public void AnExchangeCode_IsSingleUseAndExpiresAfterAMinute()
    {
        var clock = new Clock();
        var store = new OidcFlowStore(clock);
        var used = store.AddExchange(7, "alice", "https://a", "s1");
        var stale = store.AddExchange(8, "bob", "https://a", "s2");

        Assert.Equal(7, store.TakeExchange(used)?.UserID);
        Assert.Null(store.TakeExchange(used));

        clock.Now += OidcFlowStore.ExchangeLifetime + TimeSpan.FromSeconds(1);
        Assert.Null(store.TakeExchange(stale));
    }

    [Fact]
    public void UnknownOrEmptyKeys_ReturnNothing()
    {
        var store = new OidcFlowStore(new Clock());

        Assert.Null(store.TakeLogin(null));
        Assert.Null(store.TakeLogin(""));
        Assert.Null(store.TakeExchange("nope"));
    }

    [Fact]
    public void PendingLogins_AreCapped_AndExpiredOnesFreeUpRoom()
    {
        var clock = new Clock();
        var store = new OidcFlowStore(clock);
        for (var i = 0; i < 2000; i++)
            store.AddLogin("n", "v", "/webui", "https://x/callback");

        var ex = Assert.Throws<OidcException>(() => store.AddLogin("n", "v", "/webui", "https://x/callback"));
        Assert.Equal("busy", ex.Code);

        clock.Now += OidcFlowStore.LoginLifetime + TimeSpan.FromSeconds(1);
        store.AddLogin("n", "v", "/webui", "https://x/callback");
    }

    [Fact]
    public void Challenge_MatchesTheRfc7636Example()
        => Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", OidcFlowStore.ChallengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

    [Fact]
    public void ALinkTicket_IsSingleUseAndExpires()
    {
        var clock = new Clock();
        var store = new OidcFlowStore(clock);
        var used = store.AddLinkTicket(4);
        var stale = store.AddLinkTicket(5);

        Assert.Equal(4, store.TakeLinkTicket(used)?.UserID);
        Assert.Null(store.TakeLinkTicket(used));

        clock.Now += OidcFlowStore.ExchangeLifetime + TimeSpan.FromSeconds(1);
        Assert.Null(store.TakeLinkTicket(stale));
    }

    [Fact]
    public void ALoginStartedForLinking_CarriesTheUserThroughTheRedirect()
    {
        var store = new OidcFlowStore(new Clock());
        var state = store.AddLogin("n", "v", "/webui", "https://x/callback", linkUserId: 7);

        Assert.Equal(7, store.TakeLogin(state)?.LinkUserId);
    }
}
