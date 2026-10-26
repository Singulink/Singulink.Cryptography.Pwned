namespace Singulink.Cryptography.Pwned.Service.Tests;

[TestClass]
public class RangeFileTests
{
    [TestMethod]
    [DataRow(0x00000, "ranges/000/00.bin")]
    [DataRow(0xA1B2C, "ranges/A1B/2C.bin")]
    [DataRow(0xFFFFF, "ranges/FFF/FF.bin")]
    public void GetRelativePath_SplitsPrefix(int prefix, string expected)
    {
        RangeFile.GetRelativePath(prefix).ShouldBe(expected.Replace('/', Path.DirectorySeparatorChar));
    }

    [TestMethod]
    public void GetPrefixAndSuffix_SplitHashAfterFiveHexDigits()
    {
        byte[] hash = Convert.FromHexString("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        byte[] suffix = new byte[RangeFile.SuffixSize];

        RangeFile.GetSuffix(hash, suffix);

        RangeFile.GetPrefix(hash).ShouldBe(0x5BAA6);
        Convert.ToHexString(suffix).ShouldBe("01E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    [TestMethod]
    [DataRow("W/\"0x8DED132F654ED41\"")]
    [DataRow("\"0x8DED132F654ED41\"")]
    [DataRow(null)]
    public void Header_RoundTripsETag(string? etag)
    {
        byte[] header = new byte[RangeFile.HeaderSize];
        long length = RangeFile.HeaderSize + (3 * RangeFile.RecordSize);

        RangeFile.WriteHeader(header, 3, etag);

        RangeFile.TryReadHeader(header, length, out int recordCount, out string? readETag).ShouldBeTrue();
        recordCount.ShouldBe(3);
        readETag.ShouldBe(etag);
        header.AsSpan(0, 4).ToArray().ShouldBe("PWNR"u8.ToArray());
    }

    [TestMethod]
    public void Header_LongestETag_IsStored()
    {
        string etag = "\"" + new string('a', RangeFile.MaxETagLength - 2) + "\"";
        byte[] header = new byte[RangeFile.HeaderSize];

        RangeFile.WriteHeader(header, 1, etag);

        RangeFile.TryReadHeader(header, RangeFile.HeaderSize + RangeFile.RecordSize, out _, out string? readETag).ShouldBeTrue();
        readETag.ShouldBe(etag);
    }

    [TestMethod]
    [DataRow(RangeFile.MaxETagLength + 1)]
    [DataRow(200)]
    public void Header_TooLongETag_IsNotStored(int length)
    {
        byte[] header = new byte[RangeFile.HeaderSize];

        RangeFile.WriteHeader(header, 1, new string('a', length));

        RangeFile.TryReadHeader(header, RangeFile.HeaderSize + RangeFile.RecordSize, out _, out string? readETag).ShouldBeTrue();
        readETag.ShouldBeNull();
    }

    [TestMethod]
    public void Header_NonAsciiETag_IsNotStored()
    {
        byte[] header = new byte[RangeFile.HeaderSize];

        RangeFile.WriteHeader(header, 1, "\"caf\u00e9\"");

        RangeFile.TryReadHeader(header, RangeFile.HeaderSize + RangeFile.RecordSize, out _, out string? readETag).ShouldBeTrue();
        readETag.ShouldBeNull();
    }

    [TestMethod]
    public void Header_Invalid_IsRejected()
    {
        byte[] valid = new byte[RangeFile.HeaderSize];
        RangeFile.WriteHeader(valid, 2, "\"x\"");
        long length = RangeFile.HeaderSize + (2 * RangeFile.RecordSize);

        RangeFile.TryReadHeader(valid, length, out _, out _).ShouldBeTrue();

        // Wrong length for the record count
        RangeFile.TryReadHeader(valid, length + RangeFile.RecordSize, out _, out _).ShouldBeFalse();
        RangeFile.TryReadHeader(valid, length - 1, out _, out _).ShouldBeFalse();

        // Zeroed header
        RangeFile.TryReadHeader(new byte[RangeFile.HeaderSize], length, out _, out _).ShouldBeFalse();

        // Bad magic
        byte[] badMagic = (byte[])valid.Clone();
        badMagic[0] = (byte)'X';
        RangeFile.TryReadHeader(badMagic, length, out _, out _).ShouldBeFalse();

        // Unknown version
        byte[] badVersion = (byte[])valid.Clone();
        badVersion[4] = 2;
        RangeFile.TryReadHeader(badVersion, length, out _, out _).ShouldBeFalse();

        // ETag length past the header
        byte[] badETag = (byte[])valid.Clone();
        badETag[12] = RangeFile.MaxETagLength + 1;
        RangeFile.TryReadHeader(badETag, length, out _, out _).ShouldBeFalse();
    }

    [TestMethod]
    [DataRow(0L, false)]
    [DataRow(64L, false)]
    [DataRow(85L, false)]
    [DataRow(86L, true)]
    [DataRow(87L, false)]
    [DataRow(108L, true)]
    [DataRow(64L + (22 * 2000), true)]
    [DataRow(64L + (22 * 2000) + 5, false)]
    public void TryGetRecordCount_ValidatesLength(long length, bool valid)
    {
        RangeFile.TryGetRecordCount(length, out int count).ShouldBe(valid);

        if (valid)
            count.ShouldBe((int)((length - 64) / 22));
    }
}
