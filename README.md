# Shoko.Plugin.Oidc

Sign in to Shoko Server with an OpenID Connect provider.

Status: early development. The plugin loads, advertises an `oidc-login` feature once a provider is configured, and owns a small database for linking OIDC subjects to Shoko users. The sign-in flow is not implemented yet.

## Build

```bash
dotnet build
dotnet test
```
