# Provider notes

Each provider below has been signed in against, with account creation and group mapping where the provider supports groups, using an automated test run on a throwaway instance. "Create Users" was on for those runs. Versions are the ones tested.

In every case the redirect URI is `{Public Base URL}/api/plugin/Oidc/callback`.

| Provider | Version | Needs | Notes |
|---|---|---|---|
| Authentik | 2026.8.3 | Signing key on the provider | Default HS256 signing is rejected, pick an RSA/EC key. The issuer is per application: `https://<host>/application/o/<slug>/`. A provider created from a script needs `grant_types=[authorization_code]`. |
| Keycloak | 26.8.1 | Group Membership mapper for admin mapping | Issuer `https://<host>/realms/<realm>`. Add a group membership mapper with claim name `groups` and full path off. |
| Authelia | 4.39 | HTTPS, `groups` scope | OIDC needs HTTPS for Authelia itself. Use the CA Certificate File with a private CA. Add `groups` to Scopes for group mapping. Client uses `client_secret_basic` and PKCE S256. |
| Kanidm | 1.11 | HTTPS, `groups` scope, HTTPS callback | Issuer is per client: `https://<host>/oauth2/openid/<client>`. Tokens use ES256. Usernames are `user@domain` and the `groups` claim lists `name@domain` and UUIDs, so set Admin Group to the `name@domain` form. Kanidm refuses an `http` redirect URI when the client's landing URL is `https`, so serve Shoko over HTTPS. |
| Zitadel | 4.19 | Role scope for admin mapping | Roles arrive as an object under `urn:zitadel:iam:org:project:roles`. Set Admin Claim to that, Admin Group to the role key, and add the scope `urn:zitadel:iam:org:projects:roles`. Turn on role assertion in the ID token for the app. |
| Dex | latest | | No `preferred_username`, so created users are named by email. |
| Pocket ID | 2.18 | HTTPS | Session cookies are `Secure`, so Pocket ID itself must be on HTTPS. Sign-in is passkey-only. Group mapping was not tested. |
| tinyauth | 5.2 | HTTPS | The OIDC issuer must be HTTPS (it is the app URL). Group mapping was not tested. |

## Reaching the provider from the server

- If the server cannot reach the provider at its public address (hairpin NAT, split DNS), set the Backchannel URL to an address it can reach. See [Settings](../README.md#settings).
- For a provider with a private CA, put the CA certificate in a PEM file Shoko can read and set CA Certificate File.

## Not tested

Group mapping on Pocket ID and tinyauth, and any provider not listed. Other providers that follow OIDC Core should work; if one does not, the logged cause next to the failure code is the place to start.
