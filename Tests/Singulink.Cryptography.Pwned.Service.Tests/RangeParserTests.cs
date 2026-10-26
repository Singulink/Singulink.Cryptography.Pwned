using System.Buffers.Binary;
using System.Text;

namespace Singulink.Cryptography.Pwned.Service.Tests;

[TestClass]
public class RangeParserTests
{
    private const string A = "0005AD76BD555C1D6D771DE417A4B87E4B4";
    private const string B = "000A8DAE4228F821FB418F59826079BF368";
    private const string C = "FFFF5C4A486B528DD84D1F1D3F41A06E925";
    private const string NewLine = "\r\n";

    [TestMethod]
    [DataRow("\r\n", false)]
    [DataRow("\r\n", true)]
    [DataRow("\n", false)]
    [DataRow("\n", true)]
    public void Parse_LineEndings_ParsesAllRecords(string newLine, bool trailingNewLine)
    {
        string text = $"{A}:58{newLine}{B}:4{newLine}{C}:1469" + (trailingNewLine ? newLine : string.Empty);

        var records = Parse(text);

        records.Select(r => r.Suffix).ShouldBe([A, B, C]);
        records.Select(r => r.Count).ShouldBe([58, 4, 1469]);
    }

    [TestMethod]
    public void Parse_GeneratedRange_RoundTrips()
    {
        RangeEntry[] entries = TestRanges.Generate(new Random(1), 2000);

        var records = Parse(TestRanges.ToResponse(entries));

        records.Select(r => r.Suffix).ShouldBe(entries.Select(e => e.SuffixHex));
        records.Select(r => r.Count).ShouldBe(entries.Select(e => e.Count));
    }

    [TestMethod]
    public void Parse_LowerCaseHex_Parses()
    {
        var records = Parse(A.ToLowerInvariant() + ":3");

        records.ShouldHaveSingleItem().Suffix.ShouldBe(A);
    }

    [TestMethod]
    public void Parse_PaddingEntries_AreSkipped()
    {
        var records = Parse($"{A}:0\r\n{B}:4\r\n{C}:0\r\n");

        records.ShouldHaveSingleItem().Suffix.ShouldBe(B);
    }

    [TestMethod]
    public void Parse_HugeCount_IsClamped()
    {
        var records = Parse($"{A}:99999999999999999999");

        records.ShouldHaveSingleItem().Count.ShouldBe(int.MaxValue);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("\r\n")]
    [DataRow(A + ":0")]
    [DataRow(A + ":0\r\n" + B + ":0")]
    public void Parse_NoRecords_Throws(string text)
    {
        Should.Throw<InvalidDataException>(() => Parse(text));
    }

    [TestMethod]
    [DataRow(A + ":5\r\n\r\n" + B + ":4")]
    [DataRow(A + "5")]
    [DataRow(A + ":")]
    [DataRow(A + ":-5")]
    [DataRow(A + ":5 ")]
    [DataRow(A + ":5x")]
    [DataRow("G005AD76BD555C1D6D771DE417A4B87E4B4:5")]
    [DataRow("005AD76BD555C1D6D771DE417A4B87E4B4:5")]
    [DataRow("00005AD76BD555C1D6D771DE417A4B87E4B4:5")]
    [DataRow("<html>error</html>")]
    public void Parse_MalformedLine_Throws(string text)
    {
        Should.Throw<InvalidDataException>(() => Parse(text));
    }

    [TestMethod]
    [DataRow(B + ":1\r\n" + A + ":1")]
    [DataRow(A + ":1\r\n" + A + ":2")]
    [DataRow(A + ":1\r\n" + C + ":2\r\n" + B + ":3")]
    public void Parse_UnsortedOrDuplicate_Throws(string text)
    {
        var ex = Should.Throw<InvalidDataException>(() => Parse(text));
        ex.Message.ShouldContain("sorted");
    }

    [TestMethod]
    [DataRow("G005AD76BD555C1D6D771DE417A4B87E4B4:0" + NewLine + B + ":4")]
    [DataRow(B + ":0" + NewLine + A + ":4")]
    [DataRow(A + ":4" + NewLine + A + ":0")]
    [DataRow(A + ":4" + NewLine + C + ":0" + NewLine + B + ":1")]
    public void Parse_InvalidPaddingLine_Throws(string text)
    {
        Should.Throw<InvalidDataException>(() => Parse(text));
    }

    private static List<(string Suffix, int Count)> Parse(string text)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        byte[] records = new byte[RangeParser.GetMaxRecordBytes(bytes.Length)];

        int count = RangeParser.Parse(bytes, records);
        var result = new List<(string Suffix, int Count)>();

        for (int i = 0; i < count; i++)
        {
            var record = records.AsSpan(i * RangeFile.RecordSize, RangeFile.RecordSize);
            result.Add((Convert.ToHexString(record[..RangeFile.SuffixSize])[1..], BinaryPrimitives.ReadInt32LittleEndian(record[RangeFile.SuffixSize..])));
        }

        return result;
    }
}
