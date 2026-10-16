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

    [SectionName("Users")]
    [Display(Name = "Create Users", Description = "Create a local account on first sign-in. Never links to an existing account.")]
    public bool AutoCreateUsers { get; set; }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Authority) && !string.IsNullOrWhiteSpace(ClientId);
}
