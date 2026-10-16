using Shoko.Plugin.Oidc.Flow;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public class TrampolinePageTests
{
    [Fact]
    public void Success_ExchangesTheCodeAndWritesTheSessionTheWebUIReads()
    {
        var html = TrampolinePage.Success("code-1", "/webui/dashboard", "nonce-1");

        Assert.Contains("<script nonce=\"nonce-1\">", html);
        Assert.Contains("/api/plugin/Oidc/exchange", html);
        Assert.Contains("sessionStorage.setItem('state'", html);
        Assert.Contains("apiSession: { apikey, username, rememberUser: false", html);
        Assert.Contains("\"code-1\"", html);
        Assert.Contains("\"/webui/dashboard\"", html);
    }

    [Fact]
    public void Success_CannotBeBrokenOutOfTheScriptElement()
    {
        var html = TrampolinePage.Success("</script><script>alert(1)</script>", "/webui/</script>", "n");

        Assert.DoesNotContain("</script><script>alert", html);
        Assert.Equal(1, html.Split("</script>").Length - 1);
    }

    [Fact]
    public void Error_EncodesTheCode()
        => Assert.DoesNotContain("<b>", TrampolinePage.Error("<b>x</b>"));
}
