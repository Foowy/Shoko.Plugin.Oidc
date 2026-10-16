using System.Net;
using System.Text.Json;

namespace Shoko.Plugin.Oidc.Flow;

/// <summary>
///   The page the callback ends on. It trades the single-use code for a token with a same-origin request and writes the
///   session the WebUI reads on load, so no WebUI change is needed to finish a sign-in.
/// </summary>
public static class TrampolinePage
{
    public static string Success(string code, string returnUrl, string nonce)
    {
        // JSON string literals are valid JS; angle brackets are escaped so the data cannot close the script element.
        var codeJs = JsonSerializer.Serialize(code).Replace("<", "\\u003c");
        var returnJs = JsonSerializer.Serialize(returnUrl).Replace("<", "\\u003c");
        return $$"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><title>Signing in</title></head>
            <body><p>Signing in...</p>
            <script nonce="{{nonce}}">
            (async () => {
              try {
                const response = await fetch('{{OidcConstants.BasePath}}/exchange', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ code: {{codeJs}} }),
                });
                if (!response.ok) throw new Error('exchange');
                const { apikey, username } = await response.json();
                sessionStorage.setItem('state', JSON.stringify({ apiSession: { apikey, username, rememberUser: false, version: 'oidc' } }));
                location.replace({{returnJs}});
              } catch (e) {
                location.replace('{{OidcConstants.BasePath}}/error?code=exchange_failed');
              }
            })();
            </script></body></html>
            """;
    }

    public static string Error(string code)
        => $$"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><title>Sign-in failed</title></head>
            <body><p>Sign-in failed ({{WebUtility.HtmlEncode(code)}}).</p><p><a href="/webui/login">Back to the login page</a></p></body></html>
            """;
}
