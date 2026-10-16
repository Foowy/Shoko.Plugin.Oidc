using Microsoft.Extensions.DependencyInjection;
using Shoko.Abstractions.Plugin;
using Shoko.Plugin.Oidc.Data;

namespace Shoko.Plugin.Oidc;

public class ServiceRegistration : IPluginServiceRegistration
{
    public static void RegisterServices(IServiceCollection serviceCollection, IApplicationPaths applicationPaths)
        => serviceCollection.AddPluginDbContext<Plugin, OidcDbContext>("oidc");
}
