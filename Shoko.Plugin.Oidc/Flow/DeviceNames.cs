namespace Shoko.Plugin.Oidc.Flow;

public static class DeviceNames
{
    public static string Prefix(string issuer)
        => $"OIDC - {issuer} - ";
}
