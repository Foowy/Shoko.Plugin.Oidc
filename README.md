# Shoko.Plugin.Oidc

Sign in to Shoko Server with an OpenID Connect provider.

> **Alpha.** This plugin is under early development and has not been approved or tested for real use. Do not rely on it to protect a server, and expect breaking changes. This notice stays until it has been tested against real providers and approved.

Status: the plugin loads, advertises an `oidc-login` feature once a provider is configured, and owns a small database for linking OIDC subjects to Shoko users. The sign-in flow is not implemented yet.

## Build

```bash
dotnet build
dotnet test
```
