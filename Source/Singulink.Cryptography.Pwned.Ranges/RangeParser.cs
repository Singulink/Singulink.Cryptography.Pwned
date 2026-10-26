using System.Buffers.Binary;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Parses Have I Been Pwned range responses: <c>SUFFIX:COUNT</c> lines with a 35 hex digit suffix, sorted by suffix.
/// </summary>
internal static class RangeParser
{
    private const int SuffixDigits = 35;

    // Shortest possible line: 35 digits, a colon and a single count digit.
    private const int MinLineLength = SuffixDigits + 2;

    /// <summary>
    /// Gets the size of a buffer that can hold the records parsed from a response of the given length.
    /// </summary>
    public static int GetMaxRecordBytes(int responseLength) => ((responseLength / MinLineLength) + 1) * RangeFile.RecordSize;

    /// <summary>
    /// Parses a response into records. Lines with a count of zero (padding) are validated like the others, then skipped. Throws <see
    /// cref="InvalidDataException"/> if the response has a malformed or out of order line or no records.
    /// </summary>
    /// <returns>The number of records written.</returns>
    public static int Parse(ReadOnlySpan<byte> text, Span<byte> records)
    {
        int recordCount = 0;
        int lineNumber = 0;

        Span<byte> suffix = stackalloc byte[RangeFile.SuffixSize];
        Span<byte> previous = stackalloc byte[RangeFile.SuffixSize];

        while (!text.IsEmpty)
        {
            lineNumber++;

            int newLine = text.IndexOf((byte)'\n');
            ReadOnlySpan<byte> line;

            if (newLine < 0)
            {
                line = text;
                text = default;
            }
            else
            {
                line = text[..newLine];
                text = text[(newLine + 1)..];
            }

            if (line.EndsWith((byte)'\r'))
                line = line[..^1];

            if (line.Length < MinLineLength || line[SuffixDigits] != (byte)':')
                throw Error(lineNumber, "expected 35 hex digits, a colon and a count");

            int count = ParseCount(line[(SuffixDigits + 1)..], lineNumber);
            ParseSuffix(line[..SuffixDigits], suffix, lineNumber);

            if (lineNumber > 1 && previous.SequenceCompareTo(suffix) >= 0)
                throw Error(lineNumber, "suffixes are not sorted in ascending order");

            suffix.CopyTo(previous);

            if (count is 0)
                continue;

            if (records.Length < (recordCount + 1) * RangeFile.RecordSize)
                throw new ArgumentException("Records buffer is too small.", nameof(records));

            Span<byte> record = records.Slice(recordCount * RangeFile.RecordSize, RangeFile.RecordSize);
            suffix.CopyTo(record);
            BinaryPrimitives.WriteInt32LittleEndian(record[RangeFile.SuffixSize..], count);

            recordCount++;
        }

        if (recordCount is 0)
            throw new InvalidDataException("The range response has no records.");

        return recordCount;
    }

    private static void ParseSuffix(ReadOnlySpan<byte> digits, Span<byte> suffix, int lineNumber)
    {
        suffix[0] = (byte)HexValue(digits[0], lineNumber);

        for (int i = 1; i < RangeFile.SuffixSize; i++)
            suffix[i] = (byte)((HexValue(digits[(i * 2) - 1], lineNumber) << 4) | HexValue(digits[i * 2], lineNumber));
    }

    private static int HexValue(byte c, int lineNumber)
    {
        if ((uint)(c - '0') <= 9)
            return c - '0';

        int lower = c | 0x20;

        if ((uint)(lower - 'a') <= 5)
            return lower - 'a' + 10;

        throw Error(lineNumber, "invalid hex digit");
    }

    // Counts that don't fit in an int are clamped.
    private static int ParseCount(ReadOnlySpan<byte> digits, int lineNumber)
    {
        long count = 0;

        foreach (byte c in digits)
        {
            if ((uint)(c - '0') > 9)
                throw Error(lineNumber, "invalid count");

            count = Math.Min((count * 10) + (c - '0'), int.MaxValue);
        }

        return (int)count;
    }

    private static InvalidDataException Error(int lineNumber, string message) => new($"Invalid range response on line {lineNumber}: {message}.");
}
