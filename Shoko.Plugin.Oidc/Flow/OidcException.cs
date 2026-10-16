namespace Shoko.Plugin.Oidc.Flow;

/// <summary>A sign-in failed in a way the user should see as a short code, never the detail.</summary>
public sealed class OidcException(string code, string message, Exception? inner = null) : Exception(message, inner)
{
    public string Code { get; } = code;
}
