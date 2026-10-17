using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Shoko.Plugin.Oidc.Flow;

namespace Shoko.Plugin.Oidc.Tests;

/// <summary>A small in-process OIDC provider with switches for the differences real providers have.</summary>
public sealed class MockProvider : IAsyncDisposable
{
    public const string ClientId = "shoko";

    public const string ClientSecret = "s3cret";

    private readonly WebApplication _app;

    private readonly ConcurrentDictionary<string, IssuedCode> _codes = new();

    private SecurityKey _key;

    private SigningCredentials _credentials;

    private record IssuedCode(string RedirectUri, string Challenge, string Nonce, JsonObject IdClaims, JsonObject UserInfo);

    public string Origin { get; }

    public string PathPrefix { get; init; } = "";

    public bool TrailingSlashIssuer { get; init; }

    public bool UseEcdsa { get; init; }

    public string[]? AuthMethods { get; init; } = ["client_secret_basic"];

    public string Audience { get; set; } = ClientId;

    public bool OmitUserInfoEndpoint { get; init; }

    public string Authority => Origin + PathPrefix + (TrailingSlashIssuer ? "/" : "");

    public string Issuer => Authority;

    public MockProvider(string pathPrefix = "", bool trailingSlashIssuer = false, bool useEcdsa = false, string[]? authMethods = null, bool omitAuthMethods = false, bool omitUserInfo = false)
    {
        PathPrefix = pathPrefix;
        TrailingSlashIssuer = trailingSlashIssuer;
        UseEcdsa = useEcdsa;
        OmitUserInfoEndpoint = omitUserInfo;
        AuthMethods = omitAuthMethods ? null : authMethods ?? ["client_secret_basic"];

        (_key, _credentials) = NewKey();

        var port = FreePort();
        Origin = $"http://127.0.0.1:{port}";
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls(Origin);
        builder.Logging.ClearProviders();
        _app = builder.Build();
        Map(_app);
        _app.Start();
    }

    private (SecurityKey, SigningCredentials) NewKey()
    {
        if (UseEcdsa)
        {
            var key = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)) { KeyId = Guid.NewGuid().ToString("N") };
            return (key, new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256));
        }

        var rsa = new RsaSecurityKey(RSA.Create(2048)) { KeyId = Guid.NewGuid().ToString("N") };
        return (rsa, new SigningCredentials(rsa, SecurityAlgorithms.RsaSha256));
    }

    public void RotateSigningKey() => (_key, _credentials) = NewKey();

    public string IssueCode(string redirectUri, string challenge, string nonce, JsonObject idClaims, JsonObject? userInfo = null)
    {
        var code = Guid.NewGuid().ToString("N");
        _codes[code] = new IssuedCode(redirectUri, challenge, nonce, idClaims, userInfo ?? new JsonObject { ["sub"] = idClaims["sub"]?.DeepClone() });
        return code;
    }

    private void Map(IEndpointRouteBuilder app)
    {
        app.MapGet(PathPrefix + "/.well-known/openid-configuration", () =>
        {
            var doc = new JsonObject
            {
                ["issuer"] = Issuer,
                ["authorization_endpoint"] = Origin + PathPrefix + "/authorize",
                ["token_endpoint"] = Origin + PathPrefix + "/token",
                ["jwks_uri"] = Origin + PathPrefix + "/jwks",
                ["response_types_supported"] = new JsonArray("code"),
                ["subject_types_supported"] = new JsonArray("public"),
                ["id_token_signing_alg_values_supported"] = new JsonArray(UseEcdsa ? "ES256" : "RS256"),
            };
            if (!OmitUserInfoEndpoint)
                doc["userinfo_endpoint"] = Origin + PathPrefix + "/userinfo";
            if (AuthMethods is not null)
                doc["token_endpoint_auth_methods_supported"] = new JsonArray(AuthMethods.Select(m => (JsonNode)m).ToArray());
            return Results.Json(doc);
        });

        app.MapGet(PathPrefix + "/jwks", () =>
        {
            var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(_key);
            var json = new JsonObject
            {
                ["keys"] = new JsonArray(JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(new
                {
                    kty = jwk.Kty,
                    kid = jwk.Kid,
                    use = "sig",
                    alg = UseEcdsa ? "ES256" : "RS256",
                    n = jwk.N,
                    e = jwk.E,
                    crv = jwk.Crv,
                    x = jwk.X,
                    y = jwk.Y,
                }, new System.Text.Json.JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull })))
            };
            return Results.Text(json.ToJsonString(), "application/json");
        });

        app.MapPost(PathPrefix + "/token", async (HttpRequest request) =>
        {
            var form = await request.ReadFormAsync();
            var (id, secret) = ClientCredentials(request, form);
            if (id != ClientId)
                return Results.Json(new { error = "invalid_client" }, statusCode: 401);
            var method = request.Headers.Authorization.Count > 0 ? "client_secret_basic" : form.ContainsKey("client_secret") ? "client_secret_post" : "none";
            if (AuthMethods is not null && !AuthMethods.Contains(method))
                return Results.Json(new { error = "invalid_client", detail = "method not advertised" }, statusCode: 401);
            if (method != "none" && secret != ClientSecret)
                return Results.Json(new { error = "invalid_client" }, statusCode: 401);

            if (!_codes.TryRemove(form["code"].ToString(), out var issued) || issued.RedirectUri != form["redirect_uri"])
                return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
            var verifier = form["code_verifier"].ToString();
            var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            if (challenge != issued.Challenge)
                return Results.Json(new { error = "invalid_grant", detail = "pkce" }, statusCode: 400);

            var claims = new Dictionary<string, object>();
            foreach (var (name, value) in issued.IdClaims)
                claims[name] = value is JsonValue v && v.TryGetValue<string>(out var text) ? text : value!.ToJsonString();
            if (issued.Nonce.Length > 0)
                claims["nonce"] = issued.Nonce;

            var idToken = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Issuer = Issuer,
                Audience = Audience,
                Claims = claims,
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = _credentials,
            });

            var accessToken = Guid.NewGuid().ToString("N");
            _tokens[accessToken] = issued.UserInfo;
            return Results.Json(new { id_token = idToken, access_token = accessToken, token_type = "Bearer" });
        });

        app.MapGet(PathPrefix + "/userinfo", (HttpRequest request) =>
        {
            var header = request.Headers.Authorization.ToString();
            if (!header.StartsWith("Bearer ") || !_tokens.TryGetValue(header["Bearer ".Length..], out var info))
                return Results.Unauthorized();
            return Results.Text(info.ToJsonString(), "application/json");
        });
    }

    private readonly ConcurrentDictionary<string, JsonObject> _tokens = new();

    private static (string? Id, string? Secret) ClientCredentials(HttpRequest request, IFormCollection form)
    {
        var header = request.Headers.Authorization.ToString();
        if (header.StartsWith("Basic "))
        {
            var parts = Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..])).Split(':', 2);
            return (Uri.UnescapeDataString(parts[0].Replace('+', ' ')), Uri.UnescapeDataString(parts[1].Replace('+', ' ')));
        }

        return (form["client_id"], form["client_secret"]);
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}
