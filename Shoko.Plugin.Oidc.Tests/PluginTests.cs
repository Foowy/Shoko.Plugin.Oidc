using Shoko.Abstractions.Plugin.Enums;
using Shoko.Plugin.Oidc.Config;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public class PluginTests
{
    [Fact]
    public void Plugin_AdvertisesNothingUntilAProviderIsConfigured()
    {
        Assert.Empty(Plugin.FeaturesFor(null));
        Assert.Empty(Plugin.FeaturesFor(new OidcConfiguration()));
        Assert.Empty(Plugin.FeaturesFor(new OidcConfiguration { Authority = "https://sso.example" }));
    }

    [Fact]
    public void Plugin_AdvertisesAnAnonymousLoginFeatureOnceConfigured()
    {
        var feature = Assert.Single(Plugin.FeaturesFor(new OidcConfiguration
        {
            Authority = "https://sso.example",
            ClientId = "shoko",
            DisplayName = "Authentik",
        }));

        Assert.Equal("login-method", feature.Name);
        Assert.Equal(PluginFeatureVisibility.Anonymous, feature.Visibility);
        Assert.Equal("Authentik", (string?)feature.Metadata?["displayName"]);
        Assert.Equal("/api/plugin/Oidc/login", (string?)feature.Metadata?["loginUrl"]);
        Assert.True(PluginFeatureIsValid(feature));
    }

    private static bool PluginFeatureIsValid(Shoko.Abstractions.Plugin.Models.PluginFeature feature)
        => Shoko.Abstractions.Plugin.Models.PluginFeature.IsValid(feature, out _);
}
