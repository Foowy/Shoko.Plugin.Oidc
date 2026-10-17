namespace Shoko.Plugin.Oidc.Flow;

/// <summary>Sends the plugin's own requests to the provider (discovery, keys, token, userinfo) to the configured backchannel address when they are aimed at the Authority's host (any scheme or port, since a provider reached over the backchannel may advertise its own urls as plain http), keeping the public Host and X-Forwarded-Proto so the provider still answers as itself.</summary>
public sealed class BackchannelHandler(Func<Config.OidcConfiguration> getConfig) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var config = getConfig();
        if (string.IsNullOrWhiteSpace(config.BackchannelUrl) || string.IsNullOrWhiteSpace(config.Authority)
            || request.RequestUri is not { } target
            || !Uri.TryCreate(config.Authority.Trim(), UriKind.Absolute, out var authority)
            || !string.Equals(target.Host, authority.Host, StringComparison.OrdinalIgnoreCase))
            return base.SendAsync(request, cancellationToken);

        if (!Uri.TryCreate(config.BackchannelUrl.Trim(), UriKind.Absolute, out var backchannel)
            || backchannel.Scheme is not ("http" or "https")
            || (backchannel.Scheme == Uri.UriSchemeHttp && !config.AllowInsecureHttp))
            throw new HttpRequestException("The backchannel URL is not a valid https address, or plain http is not allowed.");

        request.Headers.Host = authority.Authority;
        request.Headers.Remove("X-Forwarded-Proto");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", authority.Scheme);
        request.RequestUri = new UriBuilder(target) { Scheme = backchannel.Scheme, Host = backchannel.Host, Port = backchannel.Port }.Uri;
        return base.SendAsync(request, cancellationToken);
    }
}
