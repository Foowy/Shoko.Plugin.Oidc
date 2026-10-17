using Shoko.Plugin.Oidc.Flow;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public class ServiceRegistrationTests
{
    [Fact]
    public void TheProviderHandler_RecyclesPooledConnections()
    {
        using var handler = ServiceRegistration.CreateHandler(new CaTrust(() => null));

        Assert.Equal(TimeSpan.FromMinutes(5), handler.PooledConnectionLifetime);
    }
}
