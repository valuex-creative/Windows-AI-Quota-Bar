using System.Text;
using QuotaBar.Core.Providers;

namespace QuotaBar.Tests;

public class AntigravityScanTests
{
    // Made-up values, written in pieces so secret scanners don't take them for real ones.
    const string Id = "123456789012-" + "abcdefghijklmnopqrstuvwxyz012345" + ".apps.google" + "usercontent.com";
    const string Secret = "GOC" + "SPX-" + "abcdefghijklmnopqrstuvwxyz01";

    static (HashSet<string> ids, HashSet<string> secrets) Scan(byte[] content)
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, content);
            var ids = new HashSet<string>(); var secrets = new HashSet<string>();
            AntigravityAccounts.ScanFile(path, ids, secrets);
            return (ids, secrets);
        }
        finally { File.Delete(path); }
    }

    static byte[] With(int size, params (int at, string text)[] parts)
    {
        var b = new byte[size];
        new Random(1).NextBytes(b);
        for (var i = 0; i < b.Length; i++) if (b[i] is (byte)'G' or (byte)'.' or (byte)'-') b[i] = 0; // no accidental matches
        foreach (var (at, text) in parts)
        {
            Encoding.Latin1.GetBytes(text).CopyTo(b, at);
            if (at > 0) b[at - 1] = 0; // random digits or letters next to a value would become part of the match
            if (at + text.Length < b.Length) b[at + text.Length] = 0;
        }
        return b;
    }

    [Fact]
    public void Finds_values_anywhere_in_a_large_file()
    {
        var (ids, secrets) = Scan(With(3_500_000, (10, Id), (3_400_000, Secret)));
        Assert.Equal([Id], ids);
        Assert.Equal([Secret], secrets);
    }

    [Theory]
    [InlineData(1 << 20)]
    [InlineData(2 << 20)]
    public void Finds_a_value_split_across_two_pieces(int boundary)
    {
        // Straddle the 1 MB piece boundary at every offset inside the value.
        for (var back = 1; back < Id.Length; back += 7)
        {
            var (ids, secrets) = Scan(With(3_000_000, (boundary - back, Id), (boundary + 500_000 - back % Secret.Length, Secret)));
            Assert.Contains(Id, ids);
            Assert.Contains(Secret, secrets);
        }
    }

    [Fact]
    public void Empty_file_gives_nothing()
    {
        var (ids, secrets) = Scan([]);
        Assert.Empty(ids);
        Assert.Empty(secrets);
    }
}
