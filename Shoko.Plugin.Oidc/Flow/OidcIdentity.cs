using System.Text.Json.Nodes;

namespace Shoko.Plugin.Oidc.Flow;

/// <summary>The verified result of a provider sign-in.</summary>
public sealed class OidcIdentity(string issuer, string subject, JsonObject claims)
{
    public string Issuer { get; } = issuer;

    public string Subject { get; } = subject;

    public JsonObject Claims { get; } = claims;

    public string GetUsername(string? configuredClaim)
    {
        foreach (var name in new[] { configuredClaim, "preferred_username", "email" })
        {
            if (string.IsNullOrWhiteSpace(name))
                continue;
            if (Claims[name] is JsonValue value && value.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text))
                return text.Trim();
        }

        return Subject;
    }

    /// <summary>Whether <paramref name="group"/> is among the values of <paramref name="claim"/>; null when the provider sent no usable value for it.</summary>
    public bool? IsInGroup(string? claim, string group)
    {
        var values = Claims[claim ?? ""] switch
        {
            JsonArray array => array.Select(n => n is JsonValue v && v.TryGetValue<string>(out var t) ? t : null).OfType<string>().ToList(),
            JsonValue value when value.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text) => [.. text.Split(' ', StringSplitOptions.RemoveEmptyEntries)],
            _ => null,
        };
        return values?.Contains(group, StringComparer.Ordinal);
    }
}
