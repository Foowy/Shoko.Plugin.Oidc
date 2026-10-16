using Microsoft.Extensions.DependencyInjection;
using Shoko.Abstractions.Config.Services;
using Shoko.Abstractions.Plugin;
using Shoko.Plugin.Oidc.Config;
using Shoko.Plugin.Oidc.Data;
using Shoko.Plugin.Oidc.Flow;

namespace Shoko.Plugin.Oidc;

public class ServiceRegistration : IPluginServiceRegistration
{
    public static void RegisterServices(IServiceCollection serviceCollection, IApplicationPaths applicationPaths)
    {
        serviceCollection.AddPluginDbContext<Plugin, OidcDbContext>("oidc");
        serviceCollection.AddHttpClient("Shoko.Plugin.Oidc", client => client.Timeout = TimeSpan.FromSeconds(30));
        serviceCollection.AddSingleton<OidcFlowStore>();
        serviceCollection.AddSingleton(provider => new OidcProviderClient(
            provider.GetRequiredService<IHttpClientFactory>().CreateClient("Shoko.Plugin.Oidc"),
            () => provider.GetRequiredService<IConfigurationService>().Load<OidcConfiguration>()));
        serviceCollection.AddSingleton<OidcUserResolver>();
    }
}
