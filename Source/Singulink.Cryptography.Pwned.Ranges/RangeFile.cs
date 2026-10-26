using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// The range file format: a 64-byte header followed by fixed-size records sorted by suffix.
/// </summary>
/// <remarks>
/// <para>
/// Header: magic "PWNR", format version (uint32 LE), record count (int32 LE), ETag length (byte) and ETag (ASCII, up to 51 bytes), zero padded.</para>
/// <para>
/// Record: the 35 hex digit hash suffix as 18 bytes big-endian (top 4 bits zero, so byte order is sort order), then the count as an int32 LE.</para>
/// </remarks>
internal static class RangeFile
{
    public const int HeaderSize = 64;
    public const int SuffixSize = 18;
    public const int RecordSize = SuffixSize + sizeof(int);
    public const int FormatVersion = 1;

    public const int TotalPrefixes = 1 << 20;

    private const int VersionOffset = 4;
    private const int RecordCountOffset = 8;
    private const int ETagLengthOffset = 12;
    private const int ETagOffset = 13;
    public const int MaxETagLength = HeaderSize - ETagOffset;

    private static ReadOnlySpan<byte> Magic => "PWNR"u8;

    /// <summary>
    /// Gets the path of a range file relative to the data folder, i.e. <c>ranges/A1B/2C.bin</c> for prefix <c>A1B2C</c>.
    /// </summary>
    public static string GetRelativePath(int prefix)
    {
        string hex = prefix.ToString("X5", CultureInfo.InvariantCulture);
        return Path.Combine("ranges", hex[..3], string.Concat(hex.AsSpan(3), ".bin"));
    }

    /// <summary>
    /// Gets the prefix of a SHA-1 hash, i.e. its first 5 hex digits (20 bits).
    /// </summary>
    public static int GetPrefix(ReadOnlySpan<byte> hash) => (hash[0] << 12) | (hash[1] << 4) | (hash[2] >> 4);

    /// <summary>
    /// Writes the 18-byte record key for the suffix of a SHA-1 hash, i.e. everything after its first 5 hex digits.
    /// </summary>
    public static void GetSuffix(ReadOnlySpan<byte> hash, Span<byte> suffix)
    {
        suffix[0] = (byte)(hash[2] & 0x0F);
        hash[3..20].CopyTo(suffix[1..]);
    }

    /// <summary>
    /// Gets the number of records in a range file from its length, or returns <see langword="false"/> if the length isn't valid.
    /// </summary>
    public static bool TryGetRecordCount(long fileLength, out int recordCount)
    {
        long recordBytes = fileLength - HeaderSize;

        if (recordBytes < RecordSize || recordBytes % RecordSize != 0 || recordBytes / RecordSize > int.MaxValue)
        {
            recordCount = 0;
            return false;
        }

        recordCount = (int)(recordBytes / RecordSize);
        return true;
    }

    /// <summary>
    /// Writes a header. ETags that are too long or not printable ASCII aren't stored.
    /// </summary>
    public static void WriteHeader(Span<byte> header, int recordCount, string? etag)
    {
        header[..HeaderSize].Clear();
        Magic.CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header[VersionOffset..], FormatVersion);
        BinaryPrimitives.WriteInt32LittleEndian(header[RecordCountOffset..], recordCount);

        if (etag is not null && IsStorableETag(etag))
        {
            header[ETagLengthOffset] = (byte)etag.Length;
            Encoding.ASCII.GetBytes(etag, header[ETagOffset..]);
        }
    }

    /// <summary>
    /// Reads and validates a header against the file length.
    /// </summary>
    public static bool TryReadHeader(ReadOnlySpan<byte> header, long fileLength, out int recordCount, out string? etag)
    {
        recordCount = 0;
        etag = null;

        if (header.Length < HeaderSize || !header.StartsWith(Magic) || BinaryPrimitives.ReadUInt32LittleEndian(header[VersionOffset..]) != FormatVersion)
            return false;

        int count = BinaryPrimitives.ReadInt32LittleEndian(header[RecordCountOffset..]);

        if (count < 1 || fileLength != HeaderSize + ((long)count * RecordSize))
            return false;

        int etagLength = header[ETagLengthOffset];

        if (etagLength > MaxETagLength)
            return false;

        ReadOnlySpan<byte> etagBytes = header.Slice(ETagOffset, etagLength);

        foreach (byte b in etagBytes)
        {
            if (b is < 0x20 or > 0x7E)
                return false;
        }

        recordCount = count;
        etag = etagLength is 0 ? null : Encoding.ASCII.GetString(etagBytes);
        return true;
    }

    /// <summary>
    /// Checks that records are strictly ascending with valid suffixes and, if <paramref name="checkCounts"/> is set, that every count is at least 1.
    /// </summary>
    public static bool AreRecordsValid(ReadOnlySpan<byte> records, bool checkCounts)
    {
        for (int offset = 0; offset + RecordSize <= records.Length; offset += RecordSize)
        {
            if (records[offset] > 0x0F)
                return false;

            if (checkCounts && BinaryPrimitives.ReadInt32LittleEndian(records.Slice(offset + SuffixSize, sizeof(int))) < 1)
                return false;

            if (offset > 0 && records.Slice(offset - RecordSize, SuffixSize).SequenceCompareTo(records.Slice(offset, SuffixSize)) >= 0)
                return false;
        }

        return true;
    }

    /// <summary>
    /// Looks up a suffix in records that are in order, e.g. a downloaded range.
    /// </summary>
    public static RangeLookupResult Find(ReadOnlySpan<byte> records, ReadOnlySpan<byte> suffix)
    {
        int index = BinarySearch(records, records.Length / RecordSize, suffix);

        if (index < 0)
            return new(RangeLookupStatus.NotFound, 0);

        return new(RangeLookupStatus.Found, BinaryPrimitives.ReadInt32LittleEndian(records.Slice((index * RecordSize) + SuffixSize, sizeof(int))));
    }

    /// <summary>
    /// Finds a suffix in the first <paramref name="count"/> records. Returns its index, or the bitwise complement of the index it would be inserted at.
    /// </summary>
    public static int BinarySearch(ReadOnlySpan<byte> records, int count, ReadOnlySpan<byte> suffix)
    {
        int low = 0;
        int high = count - 1;

        while (low <= high)
        {
            int middle = low + ((high - low) >> 1);
            int comparison = records.Slice(middle * RecordSize, SuffixSize).SequenceCompareTo(suffix);

            if (comparison is 0)
                return middle;

            if (comparison < 0)
                low = middle + 1;
            else
                high = middle - 1;
        }

        return ~low;
    }

    private static bool IsStorableETag(string etag)
    {
        if (etag.Length is 0 or > MaxETagLength)
            return false;

        foreach (char c in etag)
        {
            if (c is < (char)0x20 or > (char)0x7E)
                return false;
        }

        return true;
    }
}
