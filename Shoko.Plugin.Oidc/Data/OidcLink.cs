namespace Shoko.Plugin.Oidc.Data;

/// <summary>Ties one OIDC subject, scoped by its authority, to one Shoko user.</summary>
public class OidcLink
{
    public int ID { get; set; }

    public required string Authority { get; set; }

    public required string Subject { get; set; }

    public int UserID { get; set; }
}
