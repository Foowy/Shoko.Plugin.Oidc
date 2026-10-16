using Asp.Versioning;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Shoko.Abstractions.Config.Services;
using Shoko.Abstractions.User.Services;
using Shoko.Plugin.Oidc.Config;
using Shoko.Plugin.Oidc.Flow;

namespace Shoko.Plugin.Oidc.Controllers;

[ApiController]
[ApiVersion("1.0")]
[Route(OidcConstants.BasePath)]
public class OidcController(
    IConfigurationService configurationService,
    OidcProviderClient provider,
    OidcFlowStore store,
    OidcUserResolver resolver,
    IUserService users,
    IAuthenticationThrottleService throttle,
    ILogger<OidcController> logger) : ControllerBase
{
    private const string StateCookie = "shoko_oidc_state";

    public record ExchangeRequest(string? Code);

    [HttpGet("login")]
    public async Task<IActionResult> Login([FromQuery] string? returnUrl, CancellationToken ct)
    {
        var config = configurationService.Load<OidcConfiguration>();
        if (!config.IsConfigured)
            return ErrorPage("not_configured");

        try
        {
            var verifier = OidcFlowStore.RandomToken();
            var nonce = OidcFlowStore.RandomToken();
            var redirectUri = RedirectUri(config);
            var state = store.AddLogin(nonce, verifier, Url.IsLocalUrl(returnUrl) ? returnUrl! : "/webui", redirectUri);
            // Ties the callback to the browser that started the login, so a link carrying someone else's state is useless.
            Response.Cookies.Append(StateCookie, state, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = redirectUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase),
                Path = OidcConstants.BasePath,
                MaxAge = OidcFlowStore.LoginLifetime,
            });
            return Redirect((await provider.BuildAuthorizeUrlAsync(redirectUri, state, nonce, verifier, ct)).AbsoluteUri);
        }
        catch (OidcException ex)
        {
            logger.LogWarning("OIDC login could not start: {Code} ({Message})", ex.Code, ex.Message);
            return ErrorPage(ex.Code);
        }
    }

    [HttpGet("error")]
    public IActionResult Error([FromQuery] string? code)
        => ErrorPage(code is { Length: <= 40 } ? code : "unknown");

    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string? code, [FromQuery] string? state, [FromQuery] string? error, CancellationToken ct)
    {
        var pending = store.TakeLogin(state);
        var boundToThisBrowser = !string.IsNullOrEmpty(state) && Request.Cookies[StateCookie] == state;
        Response.Cookies.Delete(StateCookie, new CookieOptions { Path = OidcConstants.BasePath });
        if (pending is null || !boundToThisBrowser)
            return ErrorPage("invalid_state");

        if (!string.IsNullOrEmpty(error) || string.IsNullOrEmpty(code))
            return ErrorPage("provider_denied");

        try
        {
            var config = configurationService.Load<OidcConfiguration>();
            var identity = await provider.CompleteAsync(code, pending, ct);
            var user = await resolver.ResolveAsync(identity, config, ct);
            var exchange = store.AddExchange(user.LocalID, user.Username, identity.Issuer, identity.Subject);
            return Page(TrampolinePage.Success(exchange, pending.ReturnUrl, ScriptNonce()), scriptNonce: true);
        }
        catch (OidcException ex)
        {
            logger.LogWarning("OIDC sign-in failed: {Code} ({Message})", ex.Code, ex.Message);
            return ErrorPage(ex.Code);
        }
    }

    [HttpPost("exchange")]
    public async Task<IActionResult> Exchange([FromBody] ExchangeRequest request)
    {
        if (throttle.GetRemainingLockout(HttpContext) is not null)
            return StatusCode(StatusCodes.Status429TooManyRequests);

        var pending = store.TakeExchange(request.Code);
        var user = pending is null ? null : users.GetUserByID(pending.UserID);
        if (pending is null || user is null)
        {
            throttle.RegisterFailure(HttpContext);
            return Unauthorized();
        }

        var config = configurationService.Load<OidcConfiguration>();
        var token = await users.GenerateApiTokenForUser(
            user,
            $"{DeviceNamePrefix(pending.Issuer)}{pending.Subject}",
            DateTime.Now.AddHours(config.SessionHours));
        throttle.Reset(HttpContext);
        return Content(JsonSerializer.Serialize(new { apikey = token.Token, username = user.Username }), "application/json");
    }

    public static string DeviceNamePrefix(string issuer)
        => $"OIDC - {issuer} - ";

    private string RedirectUri(OidcConfiguration config)
    {
        var baseUrl = string.IsNullOrWhiteSpace(config.PublicBaseUrl)
            ? $"{Request.Scheme}://{Request.Host}"
            : config.PublicBaseUrl.Trim().TrimEnd('/');
        return baseUrl + OidcConstants.BasePath + "/callback";
    }

    private string? _nonce;

    private string ScriptNonce()
        => _nonce ??= OidcFlowStore.RandomToken();

    private ContentResult ErrorPage(string code)
        => Page(TrampolinePage.Error(code), scriptNonce: false);

    private ContentResult Page(string html, bool scriptNonce)
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers.ContentSecurityPolicy = scriptNonce
            ? $"default-src 'none'; script-src 'nonce-{ScriptNonce()}'; connect-src 'self'"
            : "default-src 'none'";
        return Content(html, "text/html");
    }
}
