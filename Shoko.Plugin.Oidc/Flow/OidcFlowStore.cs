using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Shoko.Plugin.Oidc.Flow;

public sealed record PendingLogin(string Nonce, string CodeVerifier, string ReturnUrl, string RedirectUri, DateTimeOffset ExpiresAt, int? LinkUserId = null);

public sealed record PendingLink(int UserID, DateTimeOffset ExpiresAt);

public sealed record PendingExchange(int UserID, string Issuer, string Subject, DateTimeOffset ExpiresAt);

/// <summary>In-memory, single-use state for the redirect round trip and the code the WebUI trades for a token.</summary>
public sealed class OidcFlowStore(TimeProvider? clock = null)
{
    public static readonly TimeSpan LoginLifetime = TimeSpan.FromMinutes(10);

    public static readonly TimeSpan ExchangeLifetime = TimeSpan.FromSeconds(60);

    // The maps are open to unauthenticated callers, so they are capped instead of growing without bound.
    private const int MaxEntries = 2000;

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    private readonly ConcurrentDictionary<string, PendingLogin> _logins = new();

    private readonly ConcurrentDictionary<string, PendingExchange> _exchanges = new();

    private readonly ConcurrentDictionary<string, PendingLink> _links = new();

    public string AddLogin(string nonce, string codeVerifier, string returnUrl, string redirectUri, int? linkUserId = null)
    {
        Sweep(_logins, l => l.ExpiresAt);
        // /login is anonymous, so a flood must not be able to lock everyone out until the entries expire: make room by dropping the oldest instead.
        if (_logins.Count >= MaxEntries && _logins.MinBy(pair => pair.Value.ExpiresAt).Key is { } oldest)
            _logins.TryRemove(oldest, out _);

        var state = RandomToken();
        _logins[state] = new PendingLogin(nonce, codeVerifier, returnUrl, redirectUri, _clock.GetUtcNow() + LoginLifetime, linkUserId);
        return state;
    }

    public PendingLogin? TakeLogin(string? state)
        => Take(_logins, state, l => l.ExpiresAt);

    public string AddExchange(int userId, string issuer, string subject)
    {
        Sweep(_exchanges, e => e.ExpiresAt);
        if (_exchanges.Count >= MaxEntries)
            throw new OidcException("busy", "Too many sign-ins in progress.");

        var code = RandomToken();
        _exchanges[code] = new PendingExchange(userId, issuer, subject, _clock.GetUtcNow() + ExchangeLifetime);
        return code;
    }

    public PendingExchange? TakeExchange(string? code)
        => Take(_exchanges, code, e => e.ExpiresAt);

    public string AddLinkTicket(int userId)
    {
        Sweep(_links, l => l.ExpiresAt);
        if (_links.Count >= MaxEntries)
            throw new OidcException("busy", "Too many sign-ins in progress.");

        var ticket = RandomToken();
        _links[ticket] = new PendingLink(userId, _clock.GetUtcNow() + ExchangeLifetime);
        return ticket;
    }

    public PendingLink? TakeLinkTicket(string? ticket)
        => Take(_links, ticket, l => l.ExpiresAt);

    public static string RandomToken()
        => Base64Url(RandomNumberGenerator.GetBytes(32));

    public static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string ChallengeFor(string verifier)
        => Base64Url(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)));

    private T? Take<T>(ConcurrentDictionary<string, T> map, string? key, Func<T, DateTimeOffset> expiry) where T : class
    {
        if (string.IsNullOrEmpty(key) || !map.TryRemove(key, out var value))
            return null;
        return expiry(value) > _clock.GetUtcNow() ? value : null;
    }

    private void Sweep<T>(ConcurrentDictionary<string, T> map, Func<T, DateTimeOffset> expiry)
    {
        var now = _clock.GetUtcNow();
        foreach (var (key, value) in map)
            if (expiry(value) <= now)
                map.TryRemove(key, out _);
    }
}
