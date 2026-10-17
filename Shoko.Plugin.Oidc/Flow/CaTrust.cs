using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Shoko.Plugin.Oidc.Flow;

/// <summary>Accepts a provider certificate that chains to a CA the admin configured, on top of the system trust store. Name mismatches are never excused.</summary>
public sealed class CaTrust(Func<string?> getPath)
{
    private readonly object _lock = new();

    private (string Path, DateTime Written, X509Certificate2Collection Certs)? _loaded;

    public bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None)
            return true;

        if (errors != SslPolicyErrors.RemoteCertificateChainErrors || certificate is null)
            return false;

        var roots = Load();
        if (roots is null)
            return false;

        using var custom = new X509Chain();
        custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        custom.ChainPolicy.CustomTrustStore.AddRange(roots);
        if (chain is not null)
            foreach (var element in chain.ChainElements)
                custom.ChainPolicy.ExtraStore.Add(element.Certificate);

        return custom.Build(new X509Certificate2(certificate));
    }

    private X509Certificate2Collection? Load()
    {
        var path = getPath();
        if (string.IsNullOrWhiteSpace(path))
            return null;

        lock (_lock)
        {
            try
            {
                var written = File.GetLastWriteTimeUtc(path);
                if (_loaded is not { } current || current.Path != path || current.Written != written)
                {
                    var certs = new X509Certificate2Collection();
                    certs.ImportFromPemFile(path);
                    _loaded = (path, written, certs);
                }

                return _loaded.Value.Certs.Count > 0 ? _loaded.Value.Certs : null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
            {
                _loaded = null;
                return null;
            }
        }
    }
}
