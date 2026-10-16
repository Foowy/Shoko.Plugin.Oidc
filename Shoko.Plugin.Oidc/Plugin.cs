using Newtonsoft.Json.Linq;
using Shoko.Abstractions.Config.Services;
using Shoko.Abstractions.Plugin;
using Shoko.Abstractions.Plugin.Enums;
using Shoko.Abstractions.Plugin.Models;
using Shoko.Plugin.Oidc.Config;

namespace Shoko.Plugin.Oidc;

public class Plugin : IPlugin<OidcConfiguration>
{
    private IConfigurationService? _configurationService;

    public Guid ID => new(OidcConstants.PluginId);

    public string Name => OidcConstants.Name;

    public string? Description => "Sign in to Shoko with an OpenID Connect provider.";

    public void Setup(IServiceProvider serviceProvider)
        => _configurationService = (IConfigurationService?)serviceProvider.GetService(typeof(IConfigurationService));

    public IReadOnlyList<PluginFeature> GetFeatures() => FeaturesFor(_configurationService?.Load<OidcConfiguration>());

    public static IReadOnlyList<PluginFeature> FeaturesFor(OidcConfiguration? config)
    {
        if (config is not { IsConfigured: true })
            return [];

        return
        [
            new PluginFeature
            {
                Name = OidcConstants.FeatureName,
                Visibility = PluginFeatureVisibility.Anonymous,
                Metadata = new JObject
                {
                    ["displayName"] = config.DisplayName,
                    ["loginUrl"] = $"{OidcConstants.BasePath}/login",
                },
            },
        ];
    }
}
