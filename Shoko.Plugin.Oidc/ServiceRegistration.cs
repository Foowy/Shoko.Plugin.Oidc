using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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
        serviceCollection.AddHttpClient("Shoko.Plugin.Oidc", client => client.Timeout = TimeSpan.FromSeconds(30))
            .ConfigurePrimaryHttpMessageHandler(provider =>
                CreateHandler(new CaTrust(() => provider.GetRequiredService<IConfigurationService>().Load<OidcConfiguration>().CaCertificatePath)))
            .AddHttpMessageHandler(provider => new BackchannelHandler(() => provider.GetRequiredService<IConfigurationService>().Load<OidcConfiguration>()));
        serviceCollection.AddSingleton<OidcFlowStore>();
        serviceCollection.AddSingleton(provider => new OidcProviderClient(
            provider.GetRequiredService<IHttpClientFactory>().CreateClient("Shoko.Plugin.Oidc"),
            () => provider.GetRequiredService<IConfigurationService>().Load<OidcConfiguration>(),
            provider.GetService<ILogger<OidcProviderClient>>()));
        serviceCollection.AddSingleton<OidcUserResolver>();
    }

    /// <summary>The provider client is a singleton that keeps one HttpClient for good, so the factory never rotates its handler; the connection lifetime bounds how long a stale DNS answer or connection is reused.</summary>
    public static SocketsHttpHandler CreateHandler(CaTrust trust)
        => new()
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            SslOptions = { RemoteCertificateValidationCallback = trust.Validate },
        };
}
