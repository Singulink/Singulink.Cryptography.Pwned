using System.Buffers.Binary;
using Microsoft.Extensions.Logging;

namespace Singulink.Cryptography.Pwned.Service.Tests;

[TestClass]
public sealed class RangeLookupTests : IDisposable
{
    private const int Prefix = 0x00ABC;

    private readonly TempFolder _folder = new();
    private readonly RangeStore _store;

    public RangeLookupTests()
    {
        _store = new RangeStore(_folder.Path);
    }

    public void Dispose() => _folder.Dispose();

    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(RangeStore.WindowRecords - 1)]
    [DataRow(RangeStore.WindowRecords)]
    [DataRow(RangeStore.WindowRecords + 1)]
    [DataRow(500)]
    [DataRow(2000)]
    [DataRow(10_000)]
    public async Task Lookup_UniformRange_FindsEveryRecordAndRejectsAbsentHashes(int count)
    {
        var random = new Random(count);
        RangeEntry[] entries = TestRanges.Generate(random, count);
        await TestRanges.WriteAsync(_store, Prefix, entries);

        await ShouldFindAllAsync(entries);
        await ShouldNotFindAbsentAsync(entries, random);
    }

    [TestMethod]
    [DataRow(0.0, 0.01)]
    [DataRow(0.99, 0.01)]
    [DataRow(0.495, 0.01)]
    [DataRow(0.0, 0.001)]
    [DataRow(0.999, 0.001)]
    public async Task Lookup_SkewedRange_MovesWindowsAndFindsEveryRecord(double bandStart, double bandWidth)
    {
        // All suffixes in a narrow band, so predictions are far off and the search has to move through many windows in one direction or the other.

        var random = new Random(42);
        RangeEntry[] entries = TestRanges.Generate(random, 5000, bandStart, bandWidth);
        await TestRanges.WriteAsync(_store, Prefix, entries);

        await ShouldFindAllAsync(entries);
        await ShouldNotFindAbsentAsync(entries, random);
    }

    [TestMethod]
    public async Task Lookup_TwoClusters_FindsEveryRecord()
    {
        // Half the records at each end of the suffix range: predictions in the middle are off in both directions.

        var random = new Random(7);
        RangeEntry[] entries = [.. TestRanges.Generate(random, 1000, 0, 0.01), .. TestRanges.Generate(random, 1000, 0.99, 0.01)];
        await TestRanges.WriteAsync(_store, Prefix, entries);

        await ShouldFindAllAsync(entries);
        await ShouldNotFindAbsentAsync(entries, random);
    }

    [TestMethod]
    public async Task Lookup_MissingRange_IsUnavailable()
    {
        RangeLookupResult result = await _store.LookupAsync(new byte[20]);

        result.Status.ShouldBe(RangeLookupStatus.Unavailable);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(RangeFile.HeaderSize)]
    [DataRow(RangeFile.HeaderSize + RangeFile.RecordSize - 1)]
    [DataRow(RangeFile.HeaderSize + (10 * RangeFile.RecordSize) + 5)]
    public async Task Lookup_InvalidLength_IsUnavailable(int length)
    {
        RangeEntry[] entries = TestRanges.Generate(new Random(1), 20);
        await TestRanges.WriteAsync(_store, Prefix, entries);

        string path = _store.GetRangePath(Prefix);

        using (var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite))
            stream.SetLength(length);

        RangeLookupResult result = await _store.LookupAsync(entries[0].GetHash(Prefix));

        result.Status.ShouldBe(RangeLookupStatus.Unavailable);
    }

    [TestMethod]
    public void Lookup_WrongHashLength_Throws()
    {
        Should.Throw<ArgumentException>(() => _store.LookupAsync(new byte[19]).AsTask());
    }

    [TestMethod]
    public async Task Lookup_PrefixBeyondTestPrefixCount_IsUnavailable()
    {
        var store = new RangeStore(_folder.Path, 16);
        RangeEntry[] entries = TestRanges.Generate(new Random(1), 5);
        await TestRanges.WriteAsync(_store, 16, entries);

        (await store.LookupAsync(entries[0].GetHash(16))).Status.ShouldBe(RangeLookupStatus.Unavailable);
        (await _store.LookupAsync(entries[0].GetHash(16))).Status.ShouldBe(RangeLookupStatus.Found);
    }

    [TestMethod]
    public async Task Scan_CountsValidFilesOnly()
    {
        var store = new RangeStore(_folder.Path, 600);
        RangeEntry[] entries = TestRanges.Generate(new Random(1), 5);

        foreach (int prefix in new[] { 0, 1, 255, 256, 599 })
            await TestRanges.WriteAsync(store, prefix, entries);

        // Not counted: an invalid length, a file beyond the prefix count, temp files and other names.
        await TestRanges.WriteAsync(store, 300, entries);
        File.WriteAllBytes(store.GetRangePath(300), new byte[RangeFile.HeaderSize + 3]);
        Directory.CreateDirectory(Path.Combine(_folder.Path, "ranges", "002"));
        File.WriteAllBytes(Path.Combine(_folder.Path, "ranges", "002", "58.bin"), new byte[RangeFile.HeaderSize + RangeFile.RecordSize]);
        File.WriteAllBytes(store.GetRangePath(1) + ".0123.tmp", new byte[RangeFile.HeaderSize + RangeFile.RecordSize]);
        File.WriteAllBytes(Path.Combine(_folder.Path, "ranges", "000", "xx.bin"), new byte[RangeFile.HeaderSize + RangeFile.RecordSize]);

        var scanned = new RangeStore(_folder.Path, 600);
        scanned.StoredRanges.ShouldBeNull();

        await scanned.ScanAsync();

        scanned.StoredRanges.ShouldBe(5);
    }

    [TestMethod]
    public async Task Lookup_DoesNotChangeStoredRanges()
    {
        // Only the scan, the sync and writes mark ranges as stored or missing; a lookup only unmarks ranges it finds invalid.
        var store = new RangeStore(_folder.Path, 16);
        RangeEntry[] entries = TestRanges.Generate(new Random(1), 5);
        await TestRanges.WriteAsync(store, 3, entries);
        await store.ScanAsync();
        store.StoredRanges.ShouldBe(1);

        (await store.LookupAsync(entries[0].GetHash(3))).Status.ShouldBe(RangeLookupStatus.Found);
        File.Delete(store.GetRangePath(3));

        (await store.LookupAsync(entries[0].GetHash(3))).Status.ShouldBe(RangeLookupStatus.Unavailable);
        store.StoredRanges.ShouldBe(1);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task Lookup_RightLengthWithBadHeader_IsUnavailableAndUnmarked(bool wrongRecordCount)
    {
        var logger = new FakeLogger();
        RangeEntry[] entries = TestRanges.Generate(new Random(1), 500);
        await TestRanges.WriteAsync(new RangeStore(_folder.Path, 16), 3, entries);

        string path = _store.GetRangePath(3);
        byte[] bytes = File.ReadAllBytes(path);

        if (wrongRecordCount)
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8), 499);
        else
            bytes.AsSpan(0, RangeFile.HeaderSize).Clear();

        File.WriteAllBytes(path, bytes);

        // The length is right, so the scan counts the range as stored.
        var store = new RangeStore(_folder.Path, 16, logger);
        await store.ScanAsync();
        store.StoredRanges.ShouldBe(1);

        foreach (RangeEntry entry in entries.Take(5))
            (await store.LookupAsync(entry.GetHash(3))).Status.ShouldBe(RangeLookupStatus.Unavailable);

        store.StoredRanges.ShouldBe(0);
        logger.Count("Range 00003").ShouldBe(1);
        logger.Entries.ShouldContain(e => e.Level == LogLevel.Warning && e.Message.Contains("header is invalid"));
    }

    [TestMethod]
    public async Task Lookup_ZeroedRecords_IsUnavailableAndUnmarked()
    {
        var logger = new FakeLogger();
        RangeEntry[] entries = TestRanges.Generate(new Random(1), 2000);
        await TestRanges.WriteAsync(new RangeStore(_folder.Path, 16), 3, entries);

        // Zero 4 KB in the middle, like a bad copy of the folder or clusters lost by hardware that ignores flushes.
        string path = _store.GetRangePath(3);
        byte[] bytes = File.ReadAllBytes(path);
        bytes.AsSpan(RangeFile.HeaderSize + (1000 * RangeFile.RecordSize), 4096).Clear();
        File.WriteAllBytes(path, bytes);

        var store = new RangeStore(_folder.Path, 16, logger);
        await store.ScanAsync();

        // Records far from the damage are still found, but a lookup that reads it marks the range for downloading again.
        (await store.LookupAsync(entries[10].GetHash(3))).Status.ShouldBe(RangeLookupStatus.Found);
        (await store.LookupAsync(entries[1050].GetHash(3))).Status.ShouldBe(RangeLookupStatus.Unavailable);
        (await store.LookupAsync(entries[1060].GetHash(3))).Status.ShouldBe(RangeLookupStatus.Unavailable);

        store.StoredRanges.ShouldBe(0);
        logger.Count("Range 00003").ShouldBe(1);

        store.ReadHeader(3, out _, out _).ShouldBe(RangeFileStatus.Valid);
        store.ReadHeader(3, out _, out _, checkRecords: true).ShouldBe(RangeFileStatus.Invalid);
    }

    [TestMethod]
    public async Task MarkInvalid_AfterRangeWasRewritten_KeepsItStored()
    {
        var store = new RangeStore(_folder.Path, 16, new FakeLogger());
        await TestRanges.WriteAsync(store, 3, TestRanges.Generate(new Random(1), 5));
        await store.ScanAsync();

        // A lookup that started before the rewrite found the old file invalid.
        int generation = store.GetGeneration(3);
        await TestRanges.WriteAsync(store, 3, TestRanges.Generate(new Random(2), 5));

        store.MarkInvalid(3, generation, "it is a test");
        store.IsStored(3).ShouldBeTrue();

        store.MarkInvalid(3, store.GetGeneration(3), "it is a test");
        store.IsStored(3).ShouldBeFalse();
    }

    [TestMethod]
    public async Task Lookup_UnreadableFile_IsUnavailableInsteadOfThrowing()
    {
        RangeEntry[] entries = TestRanges.Generate(new Random(1), 5);
        string path = _store.GetRangePath(Prefix);

        // A folder where the file should be can't be opened as a file.
        Directory.CreateDirectory(path);
        (await _store.LookupAsync(entries[0].GetHash(Prefix))).Status.ShouldBe(RangeLookupStatus.Unavailable);
        Directory.Delete(path);

        await TestRanges.WriteAsync(_store, Prefix, entries);

        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
            (await _store.LookupAsync(entries[0].GetHash(Prefix))).Status.ShouldBe(RangeLookupStatus.Unavailable);

        (await _store.LookupAsync(entries[0].GetHash(Prefix))).Status.ShouldBe(RangeLookupStatus.Found);
    }

    [TestMethod]
    public async Task Scan_CanceledWait_DoesNotCancelTheScanForOthers()
    {
        await TestRanges.WriteAsync(_store, Prefix, TestRanges.Generate(new Random(1), 5));
        var store = new RangeStore(_folder.Path);

        await Should.ThrowAsync<OperationCanceledException>(() => store.ScanAsync(new CancellationToken(canceled: true)));
        await store.ScanAsync();

        store.StoredRanges.ShouldBe(1);
    }

    [TestMethod]
    public async Task Lookup_WhileRangeIsRewritten_AlwaysFindsCommonRecords()
    {
        var random = new Random(5);
        RangeEntry[] common = TestRanges.Generate(random, 300);
        RangeEntry[] first = Merge(common, TestRanges.Generate(random, 300));
        RangeEntry[] second = Merge(common, TestRanges.Generate(random, 300));
        await TestRanges.WriteAsync(_store, Prefix, first);

        using var cts = new CancellationTokenSource();
        int lookups = 0;

        Task[] readers = [.. Enumerable.Range(0, 4).Select(seed => Task.Run(async () => {
            var readerRandom = new Random(seed);

            while (!cts.IsCancellationRequested)
            {
                RangeEntry entry = common[readerRandom.Next(common.Length)];
                (await _store.LookupAsync(entry.GetHash(Prefix))).ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, entry.Count));
                Interlocked.Increment(ref lookups);
            }
        }))];

        try
        {
            // Every rewrite has to succeed even though lookups keep the file open.
            for (int i = 0; i < 50; i++)
                await TestRanges.WriteAsync(_store, Prefix, i % 2 is 0 ? second : first);
        }
        finally
        {
            await cts.CancelAsync();
            await Task.WhenAll(readers);
        }

        lookups.ShouldBeGreaterThan(0);

        static RangeEntry[] Merge(RangeEntry[] a, RangeEntry[] b) =>
            [.. a.Concat(b).DistinctBy(e => e.SuffixHex).Order(Comparer<RangeEntry>.Create((x, y) => TestRanges.SuffixComparer.Compare(x.Suffix, y.Suffix)))];
    }

    [TestMethod]
    public async Task WriteRange_ReplacesFileThatIsOpenForReading()
    {
        RangeEntry[] first = TestRanges.Generate(new Random(1), 50);
        RangeEntry[] second = TestRanges.Generate(new Random(2), 60);
        await TestRanges.WriteAsync(_store, Prefix, first);

        // A reader that shares delete access, like a lookup, doesn't block the rename and keeps reading the old file.
        string path = _store.GetRangePath(Prefix);
        using var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);

        await TestRanges.WriteAsync(_store, Prefix, second);

        reader.Length.ShouldBe(RangeFile.HeaderSize + (first.Length * RangeFile.RecordSize));
        (await _store.LookupAsync(second[0].GetHash(Prefix))).Status.ShouldBe(RangeLookupStatus.Found);
        Directory.GetFiles(Path.GetDirectoryName(path)!, "*.tmp").ShouldBeEmpty();
    }

    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    public async Task WriteRange_RenameFailsEveryRetry_ThrowsAndKeepsOldFile()
    {
        RangeEntry[] first = TestRanges.Generate(new Random(1), 50);
        await TestRanges.WriteAsync(_store, Prefix, first);

        string path = _store.GetRangePath(Prefix);
        byte[] before = File.ReadAllBytes(path);

        // A reader that doesn't share delete access blocks the rename on Windows.
        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var ex = await Should.ThrowAsync<Exception>(() => TestRanges.WriteAsync(_store, Prefix, TestRanges.Generate(new Random(2), 60)));
            ex.ShouldBeAssignableTo<IOException>();
        }

        File.ReadAllBytes(path).ShouldBe(before);
        Directory.GetFiles(Path.GetDirectoryName(path)!, "*.tmp").ShouldBeEmpty();
        (await _store.LookupAsync(first[0].GetHash(Prefix))).Status.ShouldBe(RangeLookupStatus.Found);
    }

    private async Task ShouldFindAllAsync(RangeEntry[] entries)
    {
        foreach (RangeEntry entry in entries)
        {
            RangeLookupResult result = await _store.LookupAsync(entry.GetHash(Prefix));

            result.Status.ShouldBe(RangeLookupStatus.Found, entry.SuffixHex);
            result.Count.ShouldBe(entry.Count, entry.SuffixHex);
        }
    }

    private async Task ShouldNotFindAbsentAsync(RangeEntry[] entries, Random random)
    {
        var present = entries.Select(e => e.SuffixHex).ToHashSet();
        List<byte[]> absent = [new byte[RangeFile.SuffixSize], [0x0F, .. Enumerable.Repeat((byte)0xFF, RangeFile.SuffixSize - 1)]];

        // Hashes next to stored ones, and random ones (which land in the bands of skewed ranges, or anywhere).
        foreach (RangeEntry entry in entries.Where((_, i) => i % 7 is 0))
        {
            byte[] next = (byte[])entry.Suffix.Clone();
            next[^1] ^= 1;
            absent.Add(next);
        }

        for (int i = 0; i < 500; i++)
            absent.Add(TestRanges.CreateSuffix(random, random.NextDouble()));

        foreach (byte[] suffix in absent)
        {
            var entry = new RangeEntry(suffix, 1);

            if (present.Contains(entry.SuffixHex))
                continue;

            RangeLookupResult result = await _store.LookupAsync(entry.GetHash(Prefix));
            result.Status.ShouldBe(RangeLookupStatus.NotFound, entry.SuffixHex);
        }
    }
}
