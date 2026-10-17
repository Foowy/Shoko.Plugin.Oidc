# Shoko.Plugin.Oidc

Sign in to Shoko Server with an OpenID Connect provider (Authentik, Keycloak, Authelia, Zitadel, Kanidm, Dex, Pocket ID, tinyauth and others).

> **Alpha.** This plugin is under early development and has not been approved for real use. Do not rely on it to protect a server, and expect breaking changes. This notice stays until it has been approved.

It is plain OIDC Core with discovery and the authorization code flow with PKCE. There is no code specific to any provider; differences are handled with settings. See [docs/providers.md](docs/providers.md) for what each tested provider needs.

## How it works

1. The WebUI login page shows a "Sign in with {name}" button. It appears for the `login-method` feature this plugin advertises at `/api/v3/Plugin/Features` (metadata `displayName` and `loginUrl`). This needs a WebUI that reads that feature ([ShokoAnime/Shoko-WebUI#1512](https://github.com/ShokoAnime/Shoko-WebUI/pull/1512), still a draft). Without it, send people to `{your Shoko URL}/api/plugin/Oidc/login` directly.
2. The browser goes to the provider, then back to `/api/plugin/Oidc/callback`.
3. The plugin checks the ID token (signature, issuer, audience, nonce, expiry), merges userinfo claims when the provider has a userinfo endpoint, and finds the Shoko user linked to that identity.
4. The callback page trades a single-use code (valid about 60 seconds) for a Shoko API token and stores the session where the WebUI reads it, then sends the browser to the WebUI.

A sign-in never matches an existing Shoko account by username or email. An identity is tied to a user through a link (see [Linking](#linking-an-account)), or a new account is created when "Create Users" is on.

## Install

Build the plugin (see [Build](#build)) and copy the output into a folder named after the plugin in Shoko's plugin directory, then restart Shoko:

```
<Shoko home>/Shoko.CLI/plugins/Oidc/
  Shoko.Plugin.Oidc.dll
  Shoko.Plugin.Oidc.deps.json
```

The folder has to be under `Shoko.CLI/plugins/`. In Docker that is `/home/shoko/.shoko/Shoko.CLI/plugins/` inside the container.

The plugin is built against `Shoko.Abstractions` 6.0.0-alpha.107 and `Microsoft.IdentityModel` 8.16.0. The IdentityModel version must match what the Shoko host ships, or the plugin fails to load with type errors.

## Set up

1. At your provider, create a confidential OIDC client with the redirect URI `{Public Base URL}/api/plugin/Oidc/callback`. Use the authorization code flow, PKCE with S256, and sign ID tokens with RS256, PS256 or ES256 (HS256 is rejected).
2. In Shoko, open the plugin's configuration (OIDC Sign-in) and set at least Authority, Client ID, Client Secret and Public Base URL.
3. Decide how users get accounts: turn on "Create Users", or link existing accounts (below).

The sign-in button only appears once Authority and Client ID are set.

## Settings

| Setting | Default | What it does |
|---|---|---|
| Display Name | `SSO` | Text of the sign-in button. |
| Authority | | Issuer URL of the provider. Discovery is read from `{Authority}/.well-known/openid-configuration`; a full discovery URL is also accepted. |
| Client ID, Client Secret | | The client you created at the provider. The secret is masked in the UI. |
| Backchannel URL | | Address Shoko itself uses to reach the provider when the Authority is not reachable from the server, for example `http://authentik:9000` inside a Docker network. Only scheme, host and port are used. Requests to the Authority's host go there with the original `Host` header and `X-Forwarded-Proto`. Browsers still use the Authority. |
| Public Base URL | | Address users reach Shoko at, for example `https://shoko.example.com`. Used to build the redirect URI. If blank, the address of the incoming request is used. |
| Scopes | `openid profile email` | Space separated. Add `groups` (or your provider's equivalent) for group mapping. |
| Token Authentication | Auto | How the client authenticates at the token endpoint. Auto follows what the provider advertises (basic, then post). |
| Allow Plain HTTP | off | Allows `http` for the Authority, provider endpoints and the Backchannel URL. Only for a provider on a trusted network. |
| CA Certificate File | | Path to a PEM file with the CA that signed the provider's certificate, for private or self-signed CAs. Trusted in addition to the system store. A name mismatch is never excused, and an unreadable file trusts nothing extra. |
| Username Claim | `preferred_username` | Claim used as the username of created accounts. Falls back to `preferred_username`, then `email`, then the subject. |
| Admin Claim | `groups` | Claim that lists the user's groups or roles. |
| Admin Group | | If set, members are made Shoko admins on every sign-in and everyone else is demoted. Blank leaves admins to Shoko. |
| Session Hours | 168 | How long a sign-in stays valid. |
| Create Users | off | Create a local account on first sign-in. Created accounts are never admins unless the Admin Group says so. |

### Admin group mapping

With Admin Group set, each sign-in compares the user's `Admin Claim` with the group:

- The claim can be a list of strings, a space separated string, or an object whose keys are the roles (Zitadel sends roles that way).
- The match is exact. Providers differ in what they put there: Kanidm lists `name@domain` and UUIDs, Zitadel lists role keys.
- If the provider sends no value for the claim, nothing changes. An empty list counts as "not a member".
- The last remaining admin is never demoted.

## Linking an account

To use an existing Shoko account, link it to the provider identity while signed in to Shoko. There is no UI for this yet; use the API with your Shoko API key (`apikey` header):

| Request | What it does |
|---|---|
| `POST /api/plugin/Oidc/link/start` | Returns `{"url": "..."}`. Open `{Shoko URL}{url}` in a browser, sign in at the provider, and the identity is linked. The link is single-use and valid for about a minute. |
| `GET /api/plugin/Oidc/link` | Lists the providers the current user is linked to. |
| `DELETE /api/plugin/Oidc/link` | Unlinks the current user. Tokens issued by those sign-ins stop working; other tokens (such as password logins) are kept. |
| `DELETE /api/plugin/Oidc/link/{userId}` | Admin only. Unlinks another user. |

One identity maps to one user and a user can have one identity per provider. Deleting a Shoko user also frees its identity.

## Security notes

- Never links or creates an account by matching a username or email on an existing account. A name clash on creation fails with `username_taken`.
- The sign-in is bound to the browser that started it with an `HttpOnly`, `SameSite=Lax` cookie, and the state, nonce and PKCE verifier are single-use.
- The redirect after sign-in is only followed if it is a path on your Shoko server.
- Use HTTPS in front of Shoko. Some providers (Kanidm, Authelia, Pocket ID, tinyauth) refuse plain `http` callbacks or cookies.
- The exchange endpoint is throttled with Shoko's authentication throttle.

## Troubleshooting

A failed sign-in ends on a page showing a code. The plugin also logs the code with the underlying cause. A userinfo endpoint that fails is logged as a warning and its claims are skipped, so check the log if group mapping does nothing.

| Code | Usual cause |
|---|---|
| `not_configured` | Authority or Client ID is empty. |
| `discovery_failed`, `bad_discovery`, `provider_unreachable` | Shoko cannot reach or read the provider. Check the Authority, Backchannel URL, DNS, and CA Certificate File. |
| `insecure_endpoint` | The provider advertised an `http` endpoint and Allow Plain HTTP is off. |
| `token_failed` | The provider refused the code exchange: wrong client secret, redirect URI mismatch, or the wrong Token Authentication. |
| `invalid_id_token`, `nonce_mismatch`, `no_id_token`, `no_subject`, `subject_mismatch` | The ID token did not validate. Check the signing algorithm (RS256, PS256, ES256 only) and that the client ID is the audience. A rotated provider key is picked up on the next sign-in. |
| `not_linked` | The identity is not linked and Create Users is off. |
| `username_taken` | Create Users is on but a Shoko user already has that name. Link the account instead. |
| `subject_taken` | While linking: the identity already belongs to another user. |
| `user_already_linked` | While linking: this user is already linked to another identity from the same provider. |
| `invalid_link`, `link_failed` | The link request expired, was reused, or could not be saved. |
| `user_missing` | The linked Shoko user was deleted while a sign-in was in flight. |
| `invalid_state` | The sign-in cookie is missing, expired or belongs to another sign-in, for example when two tabs started a sign-in at once or the page was reloaded. Start again. |
| `provider_denied` | The provider refused the sign-in or the user declined it. |
| `exchange_failed` | The final step that trades the sign-in for a Shoko session failed. Start again. |
| `userinfo_failed` | The provider's userinfo endpoint answered something other than a JSON object (a signed JWT response is not supported). |
| `sign_in_failed` | Something unexpected failed after the provider accepted the sign-in, for example Shoko rejected the new username. The cause is in the log. |
| `busy` | Too many sign-ins are waiting for their code or link at once. Pending sign-ins are dropped oldest first when 2000 are in flight, so a flood of `/login` requests slows people down but does not lock them out; rate limit that path at your reverse proxy. |

## Build

```bash
dotnet build
dotnet test
```

## License

See [LICENSE](LICENSE).
