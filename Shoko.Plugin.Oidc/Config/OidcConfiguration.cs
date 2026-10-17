using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Shoko.Abstractions.Config;
using Shoko.Abstractions.UI.Attributes;

namespace Shoko.Plugin.Oidc.Config;

[Display(Name = "OIDC Sign-in")]
public class OidcConfiguration : IPluginConfiguration, IVisibleConfiguration
{
    [SectionName("Provider")]
    [Display(Name = "Display Name", Description = "Shown on the sign-in button.")]
    public string DisplayName { get; set; } = "SSO";

    [SectionName("Provider")]
    [Display(Name = "Authority", Description = "Issuer URL of the OIDC provider.")]
    public string? Authority { get; set; }

    [SectionName("Provider")]
    [Display(Name = "Client ID")]
    public string? ClientId { get; set; }

    [SectionName("Provider")]
    [Display(Name = "Client Secret")]
    [PasswordPropertyText]
    public string? ClientSecret { get; set; }

    [SectionName("Provider")]
    [Display(Name = "Public Base URL", Description = "Address users reach Shoko at, for example https://shoko.example.com. Register {URL}/api/plugin/Oidc/callback as the redirect URI at the provider.")]
    public string? PublicBaseUrl { get; set; }

    [SectionName("Provider")]
    [Display(Name = "Scopes", Description = "Space separated. Add the scope your provider needs for extra claims.")]
    public string Scopes { get; set; } = "openid profile email";

    [SectionName("Provider")]
    [Display(Name = "Token Authentication", Description = "Auto follows what the provider advertises.")]
    public OidcTokenAuthMethod TokenAuthMethod { get; set; } = OidcTokenAuthMethod.Auto;

    [SectionName("Provider")]
    [Display(Name = "Allow Plain HTTP", Description = "Only for a provider on a trusted network that has no HTTPS.")]
    public bool AllowInsecureHttp { get; set; }

    [SectionName("Provider")]
    [Display(Name = "CA Certificate File", Description = "Path to a PEM file with the CA that signed the provider's certificate, for a provider with a private or self-signed CA. Trusted in addition to the system store. Leave blank otherwise.")]
    public string? CaCertificatePath { get; set; }

    [SectionName("Users")]
    [Display(Name = "Username Claim", Description = "Claim used as the username of created accounts. Falls back to preferred_username, email, then the subject.")]
    public string UsernameClaim { get; set; } = "preferred_username";

    [SectionName("Users")]
    [Display(Name = "Admin Claim", Description = "Claim that lists the user's groups or roles.")]
    public string AdminClaim { get; set; } = "groups";

    [SectionName("Users")]
    [Display(Name = "Admin Group", Description = "Members of this group are made Shoko admins on sign-in, everyone else is demoted. Leave blank to manage admins in Shoko. Nothing changes if the provider sends no value for the claim, and the last admin is never demoted.")]
    public string? AdminGroup { get; set; }

    [SectionName("Users")]
    [Display(Name = "Session Hours", Description = "How long a sign-in stays valid.")]
    [Range(1, 24 * 365)]
    public int SessionHours { get; set; } = 168;

    [SectionName("Users")]
    [Display(Name = "Create Users", Description = "Create a local account on first sign-in. Never links to an existing account.")]
    public bool AutoCreateUsers { get; set; }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Authority) && !string.IsNullOrWhiteSpace(ClientId);
}

public enum OidcTokenAuthMethod
{
    Auto,
    ClientSecretBasic,
    ClientSecretPost,
    None,
}
