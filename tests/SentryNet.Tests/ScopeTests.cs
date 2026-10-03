using System.Net;
using SentryNet.Core;

namespace SentryNet.Tests;

public sealed class ScopeTests
{
    [Theory]
    [InlineData("192.168.1.10", "192.168.1.0/24", true)]
    [InlineData("192.168.2.10", "192.168.1.0/24", false)]
    [InlineData("10.0.0.1", "10.0.0.0/8", true)]
    [InlineData("2001:db8::42", "2001:db8::/32", true)]
    [InlineData("2001:db9::42", "2001:db8::/32", false)]
    [InlineData("127.0.0.1", "::/0", false)]
    public void ChecksCidr(string address, string cidr, bool expected) => Assert.Equal(expected, ScopePolicy.InCidr(IPAddress.Parse(address), cidr));
    [Theory]
    [InlineData("192.0.2.0/30", 2)]
    [InlineData("192.0.2.0/31", 2)]
    [InlineData("192.0.2.1/32", 1)]
    public void ExpandsBoundedCidr(string cidr, int count) => Assert.Equal(count, ScopePolicy.ExpandCidr(cidr, 256).Count);
    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("192.0.2.0/33")]
    [InlineData("::/64")]
    [InlineData("192.0.2.0/-1")]
    public void RejectsOversizedOrInvalidRange(string cidr) => Assert.Throws<ArgumentException>(() => ScopePolicy.ExpandCidr(cidr, 256));
    [Theory]
    [InlineData("--script=all")]
    [InlineData("host;whoami")]
    [InlineData("https://example.test/")]
    [InlineData("*.example.test")]
    public void RejectsNonHostTargets(string target) => Assert.Throws<ArgumentException>(() => ScopePolicy.ValidateEntry(target));
    [Fact]
    public async Task RejectsUnknownHostnameBeforeDnsQuery()
    {
        var policy = new ScopePolicy(["127.0.0.1"]);
        await Assert.ThrowsAsync<ArgumentException>(() => policy.ResolveAsync(TestData.Options() with { Targets = ["unauthorized.example.invalid"] }, default));
    }
    [Fact]
    public async Task RejectsOutOfScopeAddress()
    {
        var policy = new ScopePolicy(["192.0.2.0/24"]);
        await Assert.ThrowsAsync<ArgumentException>(() => policy.ResolveAsync(TestData.Options(), default));
    }
    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    [InlineData("224.0.0.1")]
    [InlineData("ff02::1")]
    public async Task RejectsNonUnicast(string address)
    {
        var policy = new ScopePolicy([address]);
        await Assert.ThrowsAsync<ArgumentException>(() => policy.ResolveAsync(TestData.Options() with { Targets = [address], Scope = [address] }, default));
    }
    [Fact]
    public void RequiresExplicitAuthorization()
    {
        Assert.Throws<ArgumentException>(() => (TestData.Options() with { Authorized = false }).Validate());
        Assert.Throws<ArgumentException>(() => (TestData.Options() with { AuthorizationReference = "" }).Validate());
    }
    [Fact]
    public async Task ResolvesLiteralWithoutChangingName()
    {
        var target = Assert.Single(await new ScopePolicy(["127.0.0.1"]).ResolveAsync(TestData.Options(), default));
        Assert.Equal(new ResolvedTarget("127.0.0.1", "127.0.0.1"), target);
    }
}
