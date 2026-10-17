# Shoko.Plugin.Oidc

Sign in to Shoko Server with an OpenID Connect provider.

> **Alpha.** This plugin is under early development and has not been approved or tested for real use. Do not rely on it to protect a server, and expect breaking changes. This notice stays until it has been tested against real providers and approved.

Status: the authorization code flow with PKCE is implemented and covered by tests against an in-process mock provider (RS256 and ES256, basic and post client authentication, claims at userinfo, per-client issuers). It has not been run against a real provider yet. There is no linking endpoint yet, so for now an account is only created when "Create Users" is on.

How a sign-in ends: the callback page trades a single-use code for a Shoko API token and writes the session the WebUI reads, then sends the browser to the WebUI. The WebUI login page shows a sign-in button for the `login-method` feature this plugin advertises at `/api/v3/Plugin/Features` (metadata `displayName` and `loginUrl`), once the WebUI supports it.

## Build

```bash
dotnet build
dotnet test
```
