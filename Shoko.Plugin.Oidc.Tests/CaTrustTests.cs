using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shoko.Plugin.Oidc.Flow;
using Xunit;

namespace Shoko.Plugin.Oidc.Tests;

public sealed class CaTrustTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory().FullName;

    public void Dispose() => Directory.Delete(_dir, true);

    private static X509Certificate2 NewCa(string name)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static X509Certificate2 NewLeaf(X509Certificate2 ca)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=sso.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var serial = RandomNumberGenerator.GetBytes(8);
        using var signed = request.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10), serial);
        return X509CertificateLoader.LoadCertificate(signed.RawData);
    }

    private string Pem(X509Certificate2 ca)
    {
        var path = Path.Combine(_dir, Guid.NewGuid() + ".pem");
        File.WriteAllText(path, ca.ExportCertificatePem());
        return path;
    }

    private static bool Check(CaTrust trust, X509Certificate2 leaf, SslPolicyErrors errors = SslPolicyErrors.RemoteCertificateChainErrors)
        => trust.Validate(new object(), leaf, null, errors);

    [Fact]
    public void ALeafSignedByTheConfiguredCa_IsAccepted()
    {
        var ca = NewCa("Lab CA");
        Assert.True(Check(new CaTrust(() => Pem(ca)), NewLeaf(ca)));
    }

    [Fact]
    public void WithoutAConfiguredCa_ANonSystemCertificateIsRejected()
    {
        var ca = NewCa("Lab CA");
        Assert.False(Check(new CaTrust(() => null), NewLeaf(ca)));
    }

    [Fact]
    public void ALeafSignedByADifferentCa_IsRejected()
    {
        var other = NewCa("Other CA");
        Assert.False(Check(new CaTrust(() => Pem(NewCa("Lab CA"))), NewLeaf(other)));
    }

    [Fact]
    public void ANameMismatch_IsNeverExcusedByTheCa()
    {
        var ca = NewCa("Lab CA");
        Assert.False(Check(new CaTrust(() => Pem(ca)), NewLeaf(ca), SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void AnUnreadableCaFile_FailsClosed()
    {
        var ca = NewCa("Lab CA");
        Assert.False(Check(new CaTrust(() => Path.Combine(_dir, "missing.pem")), NewLeaf(ca)));
    }

    [Fact]
    public void ASystemTrustedCertificate_NeedsNoCa()
        => Assert.True(Check(new CaTrust(() => null), NewLeaf(NewCa("x")), SslPolicyErrors.None));
}
