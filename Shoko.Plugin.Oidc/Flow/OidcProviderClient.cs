using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Shoko.Plugin.Oidc.Config;

namespace Shoko.Plugin.Oidc.Flow;

/// <summary>Talks plain OIDC Core to one provider: discovery, authorize URL, code exchange, ID token and userinfo checks.</summary>
public sealed class OidcProviderClient(HttpClient http, Func<OidcConfiguration> getConfig)
{
    private static readonly string[] AllowedAlgorithms =
        ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

    private readonly object _lock = new();

    private string? _managerKey;

    private ConfigurationManager<OpenIdConnectConfiguration>? _manager;

    public async Task<Uri> BuildAuthorizeUrlAsync(string redirectUri, string state, string nonce, string codeVerifier, CancellationToken ct)
    {
        var config = Require(getConfig());
        var discovery = await GetDiscoveryAsync(config, ct);
        var endpoint = Endpoint(discovery.AuthorizationEndpoint, "authorization", config);
        return new Uri(QueryHelpers.AddQueryString(endpoint.ToString(), new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = config.ClientId,
            ["redirect_uri"] = redirectUri,
            ["scope"] = Scopes(config),
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = OidcFlowStore.ChallengeFor(codeVerifier),
            ["code_challenge_method"] = "S256",
        }));
    }

    public async Task<OidcIdentity> CompleteAsync(string code, PendingLogin pending, CancellationToken ct)
    {
        var config = Require(getConfig());
        var discovery = await GetDiscoveryAsync(config, ct);
        var tokens = await ExchangeCodeAsync(config, discovery, code, pending, ct);

        if (tokens["id_token"] is not JsonValue idTokenValue || !idTokenValue.TryGetValue<string>(out var idToken) || string.IsNullOrEmpty(idToken))
            throw new OidcException("no_id_token", "The provider returned no ID token.");

        var claims = await ValidateIdTokenAsync(config, discovery, idToken, pending.Nonce, ct);
        var subject = claims["sub"]?.GetValue<string>();
        if (string.IsNullOrEmpty(subject))
            throw new OidcException("no_subject", "The ID token has no subject.");

        if (!string.IsNullOrEmpty(discovery.UserInfoEndpoint) && tokens["access_token"] is JsonValue accessValue && accessValue.TryGetValue<string>(out var accessToken))
            await MergeUserInfoAsync(config, discovery, accessToken, subject, claims, ct);

        return new OidcIdentity(discovery.Issuer, subject, claims);
    }

    private static OidcConfiguration Require(OidcConfiguration config)
        => config.IsConfigured ? config : throw new OidcException("not_configured", "No provider is configured.");

    private static string Scopes(OidcConfiguration config)
    {
        var scopes = (config.Scopes ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        if (!scopes.Contains("openid"))
            scopes.Insert(0, "openid");
        return string.Join(' ', scopes);
    }

    private static Uri Endpoint(string? value, string name, OidcConfiguration config)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            throw new OidcException("bad_discovery", $"The provider advertises no {name} endpoint.");
        if (uri.Scheme != Uri.UriSchemeHttps && !(config.AllowInsecureHttp && uri.Scheme == Uri.UriSchemeHttp))
            throw new OidcException("insecure_endpoint", $"The {name} endpoint is not HTTPS.");
        return uri;
    }

    private async Task<OpenIdConnectConfiguration> GetDiscoveryAsync(OidcConfiguration config, CancellationToken ct)
    {
        try
        {
            return await Manager(config).GetConfigurationAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new OidcException("discovery_failed", "Could not read the provider's discovery document.", ex);
        }
    }

    private ConfigurationManager<OpenIdConnectConfiguration> Manager(OidcConfiguration config)
    {
        var address = DiscoveryAddress(config.Authority!);
        var key = $"{address}|{config.AllowInsecureHttp}";
        lock (_lock)
        {
            if (_manager is null || _managerKey != key)
            {
                _manager = new ConfigurationManager<OpenIdConnectConfiguration>(address, new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(http) { RequireHttps = !config.AllowInsecureHttp });
                _managerKey = key;
            }

            return _manager;
        }
    }

    public static string DiscoveryAddress(string authority)
    {
        const string wellKnown = ".well-known/openid-configuration";
        var trimmed = authority.Trim();
        return trimmed.EndsWith(wellKnown, StringComparison.Ordinal) ? trimmed : trimmed.TrimEnd('/') + "/" + wellKnown;
    }

    public static OidcTokenAuthMethod ResolveAuthMethod(OidcConfiguration config, ICollection<string> advertised)
    {
        if (config.TokenAuthMethod != OidcTokenAuthMethod.Auto)
            return config.TokenAuthMethod;
        if (string.IsNullOrEmpty(config.ClientSecret))
            return OidcTokenAuthMethod.None;
        if (advertised.Count is 0 || advertised.Contains("client_secret_basic"))
            return OidcTokenAuthMethod.ClientSecretBasic;
        return advertised.Contains("client_secret_post") ? OidcTokenAuthMethod.ClientSecretPost : OidcTokenAuthMethod.ClientSecretBasic;
    }

    private async Task<JsonObject> ExchangeCodeAsync(OidcConfiguration config, OpenIdConnectConfiguration discovery, string code, PendingLogin pending, CancellationToken ct)
    {
        var endpoint = Endpoint(discovery.TokenEndpoint, "token", config);
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = pending.RedirectUri,
            ["code_verifier"] = pending.CodeVerifier,
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        switch (ResolveAuthMethod(config, discovery.TokenEndpointAuthMethodsSupported))
        {
            case OidcTokenAuthMethod.ClientSecretBasic:
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes($"{FormEncode(config.ClientId!)}:{FormEncode(config.ClientSecret ?? "")}")));
                break;
            case OidcTokenAuthMethod.ClientSecretPost:
                form["client_id"] = config.ClientId!;
                form["client_secret"] = config.ClientSecret ?? "";
                break;
            default:
                form["client_id"] = config.ClientId!;
                break;
        }

        request.Content = new FormUrlEncodedContent(form);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await SendAsync(request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new OidcException("token_failed", $"The token endpoint answered {(int)response.StatusCode}.");

        return ParseObject(body, "token_failed");
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        try
        {
            return await http.SendAsync(request, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            throw new OidcException("provider_unreachable", "The provider could not be reached.", ex);
        }
    }

    private async Task<JsonObject> ValidateIdTokenAsync(OidcConfiguration config, OpenIdConnectConfiguration discovery, string idToken, string nonce, CancellationToken ct)
    {
        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(idToken, Parameters(config, discovery));
        if (!result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            Manager(config).RequestRefresh();
            discovery = await GetDiscoveryAsync(config, ct);
            result = await handler.ValidateTokenAsync(idToken, Parameters(config, discovery));
        }

        if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt)
            throw new OidcException("invalid_id_token", "The ID token did not validate.", result.Exception);

        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload)) as JsonObject
            ?? throw new OidcException("invalid_id_token", "The ID token payload is not an object.");

        if (payload["nonce"]?.GetValue<string>() != nonce)
            throw new OidcException("nonce_mismatch", "The ID token nonce does not match.");

        if (payload["aud"] is JsonArray { Count: > 1 } && payload["azp"]?.GetValue<string>() != config.ClientId)
            throw new OidcException("invalid_id_token", "The ID token was issued to another client.");

        return payload;
    }

    private static TokenValidationParameters Parameters(OidcConfiguration config, OpenIdConnectConfiguration discovery) => new()
    {
        ValidIssuer = discovery.Issuer,
        ValidAudience = config.ClientId,
        IssuerSigningKeys = discovery.SigningKeys,
        ValidAlgorithms = AllowedAlgorithms,
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(2),
    };

    private async Task MergeUserInfoAsync(OidcConfiguration config, OpenIdConnectConfiguration discovery, string accessToken, string subject, JsonObject claims, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Endpoint(discovery.UserInfoEndpoint, "userinfo", config));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
            return;

        var info = ParseObject(await response.Content.ReadAsStringAsync(ct), "userinfo_failed");
        if (info["sub"]?.GetValue<string>() != subject)
            throw new OidcException("subject_mismatch", "The userinfo subject does not match the ID token.");

        foreach (var (name, value) in info)
            if (!claims.ContainsKey(name))
                claims[name] = value?.DeepClone();
    }

    private static JsonObject ParseObject(string body, string errorCode)
    {
        try
        {
            return JsonNode.Parse(body) as JsonObject ?? throw new OidcException(errorCode, "The provider answered with something other than a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new OidcException(errorCode, "The provider answered with invalid JSON.", ex);
        }
    }

    private static string FormEncode(string value)
        => Uri.EscapeDataString(value).Replace("%20", "+");
}
