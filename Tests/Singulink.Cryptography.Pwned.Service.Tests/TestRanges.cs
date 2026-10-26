using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Singulink.Cryptography.Pwned.Service.Tests;

internal static class TestRanges
{
    public static readonly Comparer<byte[]> SuffixComparer = Comparer<byte[]>.Create((x, y) => x.AsSpan().SequenceCompareTo(y));

    /// <summary>
    /// Generates sorted random records. The suffixes are spread over the given fraction of the suffix range, so a narrow band makes a skewed range.
    /// </summary>
    public static RangeEntry[] Generate(Random random, int count, double bandStart = 0, double bandWidth = 1)
    {
        var suffixes = new SortedSet<byte[]>(SuffixComparer);

        while (suffixes.Count < count)
            suffixes.Add(CreateSuffix(random, bandStart + (random.NextDouble() * bandWidth)));

        return [.. suffixes.Select(s => new RangeEntry(s, random.Next(1, 1_000_000)))];
    }

    /// <summary>
    /// Creates a random suffix at the given fraction (0 to 1) of the suffix range.
    /// </summary>
    public static byte[] CreateSuffix(Random random, double position)
    {
        byte[] suffix = new byte[RangeFile.SuffixSize];
        random.NextBytes(suffix);

        const uint Limit = 1u << 28;
        uint top = (uint)Math.Clamp(position * Limit, 0, Limit - 1);
        BinaryPrimitives.WriteUInt32BigEndian(suffix, top);

        return suffix;
    }

    public static string ToResponse(IEnumerable<RangeEntry> entries, string newLine = "\r\n", bool trailingNewLine = false)
    {
        var sb = new StringBuilder();

        foreach (RangeEntry entry in entries)
        {
            if (sb.Length > 0)
                sb.Append(newLine);

            sb.Append(entry.SuffixHex).Append(':').Append(entry.Count.ToString(CultureInfo.InvariantCulture));
        }

        if (trailingNewLine)
            sb.Append(newLine);

        return sb.ToString();
    }

    public static Task WriteAsync(RangeStore store, int prefix, RangeEntry[] entries, string? etag = null)
    {
        byte[] buffer = new byte[RangeFile.HeaderSize + (entries.Length * RangeFile.RecordSize)];

        for (int i = 0; i < entries.Length; i++)
        {
            int offset = RangeFile.HeaderSize + (i * RangeFile.RecordSize);
            entries[i].Suffix.CopyTo(buffer, offset);
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(offset + RangeFile.SuffixSize), entries[i].Count);
        }

        return store.WriteRangeAsync(prefix, buffer, entries.Length, etag, CancellationToken.None);
    }
}

/// <summary>
/// A record in a generated range.
/// </summary>
internal sealed record RangeEntry(byte[] Suffix, int Count)
{
    /// <summary>
    /// Gets the suffix as the 35 hex digits used by the range API.
    /// </summary>
    public string SuffixHex => Convert.ToHexString(Suffix)[1..];

    public byte[] GetHash(int prefix) => Convert.FromHexString(FormatPrefix(prefix) + SuffixHex);

    public string GetHashHex(int prefix) => FormatPrefix(prefix) + SuffixHex;

    private static string FormatPrefix(int prefix) => prefix.ToString("X5", CultureInfo.InvariantCulture);
}
