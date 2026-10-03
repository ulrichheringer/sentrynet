using System.Net;
using System.Net.Sockets;

namespace SentryNet.Core;

public sealed class ScopePolicy
{
    private readonly string[] entries;
    public ScopePolicy(IEnumerable<string> scope)
    {
        entries = scope.Select(Normalize).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        foreach (var entry in entries) ValidateEntry(entry);
    }
    public static string Normalize(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
    public static void ValidateEntry(string entry)
    {
        if (entry.Contains('/')) { _ = ExpandCidr(entry, 4096, expand: false); return; }
        if (IPAddress.TryParse(entry, out _)) return;
        if (Uri.CheckHostName(entry) != UriHostNameType.Dns || entry.StartsWith('-') || entry.Length > 253)
            throw new ArgumentException($"Invalid host or CIDR: {entry}");
    }
    public bool AllowsName(string name) => entries.Contains(Normalize(name), StringComparer.OrdinalIgnoreCase);
    public bool AllowsAddress(IPAddress address) => entries.Any(e =>
        IPAddress.TryParse(e, out var ip) ? ip.Equals(address) : e.Contains('/') && InCidr(address, e));
    public bool Allows(string name, IPAddress address) => AllowsName(name) || AllowsAddress(address);
    public static bool InCidr(IPAddress address, string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) ||
            !int.TryParse(parts[1], out var bits)) return false;
        var a = address.GetAddressBytes(); var n = network.GetAddressBytes();
        if (a.Length != n.Length || bits < 0 || bits > a.Length * 8) return false;
        for (var i = 0; i < a.Length; i++)
        {
            var mask = i * 8 + 8 <= bits ? 255 : i * 8 >= bits ? 0 : 255 << (8 - (bits - i * 8));
            if ((a[i] & mask) != (n[i] & mask)) return false;
        }
        return true;
    }
    public static IReadOnlyList<string> ExpandCidr(string cidr, int maximum, bool expand = true)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out var bits) ||
            bits < 0 || bits > ip.GetAddressBytes().Length * 8) throw new ArgumentException($"Invalid CIDR: {cidr}");
        if (!expand) return [];
        if (ip.AddressFamily != AddressFamily.InterNetwork) throw new ArgumentException("IPv6 ranges are not expanded; use individual IPv6 addresses.");
        var count = 1UL << (32 - bits);
        if (count > (ulong)maximum) throw new ArgumentException($"CIDR exceeds the host limit ({maximum}).");
        var bytes = ip.GetAddressBytes();
        uint number = (uint)bytes[0] << 24 | (uint)bytes[1] << 16 | (uint)bytes[2] << 8 | bytes[3];
        var network = number & (bits == 0 ? 0 : uint.MaxValue << (32 - bits));
        var result = new List<string>();
        // /31 and /32 retain all addresses; other ranges omit network and broadcast.
        for (ulong i = count > 2 ? 1UL : 0; i < (count > 2 ? count - 1 : count); i++)
        {
            var value = network + i;
            result.Add(new IPAddress(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value }).ToString());
        }
        return result;
    }
    public async Task<IReadOnlyList<ResolvedTarget>> ResolveAsync(ScanOptions options, CancellationToken ct)
    {
        var names = options.Targets.SelectMany(t => t.Contains('/') ? ExpandCidr(t, options.MaxHosts) : new[] { Normalize(t) }).Distinct().ToArray();
        if (names.Length > options.MaxHosts) throw new ArgumentException("Target count exceeds the host limit.");
        var result = new List<ResolvedTarget>();
        foreach (var name in names)
        {
            ValidateEntry(name);
            // Reject unknown names before any resolver query; never follow wildcard scope.
            if (!IPAddress.TryParse(name, out var literal) && !AllowsName(name))
                throw new ArgumentException($"Hostname is outside explicit scope: {name}");
            var addresses = literal is not null ? new[] { literal } : await Dns.GetHostAddressesAsync(name, ct);
            if (addresses.Length == 0) throw new ArgumentException($"No address resolved for {name}");
            foreach (var address in addresses.Distinct())
            {
                if (!Allows(name, address)) throw new ArgumentException($"Address is outside scope: {address}");
                if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast) ||
                    address.IsIPv6Multicast || (address.AddressFamily == AddressFamily.InterNetwork && address.GetAddressBytes()[0] >= 224))
                    throw new ArgumentException($"Unicast targets only: {address}");
                result.Add(new(name, address.ToString()));
                if (result.Count > options.MaxHosts) throw new ArgumentException("Resolved address count exceeds host limit.");
            }
        }
        return result.OrderBy(t => t.Name, StringComparer.Ordinal).ThenBy(t => t.Address, StringComparer.Ordinal).ToArray();
    }
}
