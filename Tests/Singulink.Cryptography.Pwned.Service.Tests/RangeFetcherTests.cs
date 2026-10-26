using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Singulink.Cryptography.Pwned.Service.Tests;

[TestClass]
public sealed class RangeFetcherTests : IDisposable
{
    private const int PrefixCount = 64;

    private readonly TempFolder _folder = new();
    private readonly FakeRangeServer _server = new(PrefixCount);
    private readonly FakeLogger _logger = new();
    private readonly RangeStore _store;

    public RangeFetcherTests()
    {
        _store = new RangeStore(_folder.Path, PrefixCount, _logger);
    }

    public void Dispose()
    {
        _server.Dispose();
        _folder.Dispose();
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task Lookup_MissingRange_IsAnsweredFromTheDownloadAndStored(bool found)
    {
        RangeFetcher fetcher = CreateFetcher();
        RangeEntry[] entries = _server.GetEntries(3);
        RangeEntry entry = found ? entries[10] : GetAbsentEntry(entries);

        RangeLookupResult result = await fetcher.LookupAsync(entry.GetHash(3));

        result.ShouldBe(found ? new(RangeLookupStatus.Found, entry.Count) : new(RangeLookupStatus.NotFound, 0));
        await WaitUntilIdleAsync(fetcher);

        _server.Requests.ShouldHaveSingleItem().ShouldSatisfyAllConditions(
            r => r.Prefix.ShouldBe(3),
            r => r.IfNoneMatch.ShouldBeNull(),
            r => r.UserAgent.ShouldContain("github.com/Singulink"));

        fetcher.Downloads.ShouldBe(1);
        fetcher.Failures.ShouldBe(0);
        _logger.Count("Downloaded range 00003 on demand.").ShouldBe(1);

        // Stored like the sync stores it, with the ETag for the sync's next conditional request.
        _store.IsStored(3).ShouldBeTrue();
        _store.ReadHeader(3, out string? etag, out int recordCount, checkRecords: true).ShouldBe(RangeFileStatus.Valid);
        etag.ShouldBe(_server.GetETag(3));
        recordCount.ShouldBe(entries.Length);

        foreach (RangeEntry e in entries)
            (await _store.LookupAsync(e.GetHash(3))).ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, e.Count));

        // Later lookups are answered from the file.
        (await fetcher.LookupAsync(entries[20].GetHash(3))).ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, entries[20].Count));
        _server.Requests.Count.ShouldBe(1);
    }

    [TestMethod]
    public async Task Lookup_ConcurrentLookupsOfMissingRange_ShareOneDownload()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _server.BeforeResponse = (_, cancellationToken) => release.Task.WaitAsync(cancellationToken);

        RangeFetcher fetcher = CreateFetcher();
        RangeEntry[] entries = _server.GetEntries(5);

        Task<RangeLookupResult>[] lookups = [.. entries.Take(50).Select(e => Task.Run(() => fetcher.LookupAsync(e.GetHash(5)).AsTask()))];

        // Let every lookup find the download in progress before it completes.
        await WaitUntilAsync(() => !_server.Requests.IsEmpty);
        await Task.Delay(200);
        release.SetResult();

        RangeLookupResult[] results = await Task.WhenAll(lookups);
        await WaitUntilIdleAsync(fetcher);

        results.ShouldBe(entries.Take(50).Select(e => new RangeLookupResult(RangeLookupStatus.Found, e.Count)));
        _server.Requests.ShouldHaveSingleItem().Prefix.ShouldBe(5);
        fetcher.Downloads.ShouldBe(1);
        _store.IsStored(5).ShouldBeTrue();
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task Lookup_CorruptFile_IsDownloadedAgainAndReplaced(bool damagedRecords)
    {
        // An old version of the range, damaged like a bad copy of the folder.
        RangeEntry[] old = TestRanges.Generate(new Random(9), 2000);
        await TestRanges.WriteAsync(new RangeStore(_folder.Path, PrefixCount), 7, old, "W/\"old\"");

        string path = _store.GetRangePath(7);
        byte[] bytes = File.ReadAllBytes(path);

        if (damagedRecords)
            bytes.AsSpan(RangeFile.HeaderSize + (1000 * RangeFile.RecordSize), 4096).Clear();
        else
            bytes[0] = 0;

        File.WriteAllBytes(path, bytes);

        // The length is right, so the scan counts the range as stored until a lookup finds it invalid.
        await _store.ScanAsync();
        _store.StoredRanges.ShouldBe(1);

        RangeFetcher fetcher = CreateFetcher();
        RangeEntry[] entries = _server.GetEntries(7);

        // With damaged records, a lookup of an old record reads the damage; the new range doesn't have that record.
        RangeLookupResult result = await fetcher.LookupAsync(damagedRecords ? old[1050].GetHash(7) : entries[0].GetHash(7));

        result.ShouldBe(damagedRecords ? new(RangeLookupStatus.NotFound, 0) : new(RangeLookupStatus.Found, entries[0].Count));
        await WaitUntilIdleAsync(fetcher);

        _server.Requests.ShouldHaveSingleItem().IfNoneMatch.ShouldBeNull();
        _logger.Count("Range 00007 (").ShouldBe(1);
        _logger.Entries.ShouldContain(e => e.Level == LogLevel.Warning && e.Message.Contains(damagedRecords ? "not in order" : "header is invalid"));

        _store.ReadHeader(7, out string? etag, out _, checkRecords: true).ShouldBe(RangeFileStatus.Valid);
        etag.ShouldBe(_server.GetETag(7));
        _store.StoredRanges.ShouldBe(1);

        foreach (RangeEntry entry in entries)
            (await _store.LookupAsync(entry.GetHash(7))).ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, entry.Count));

        Directory.GetFiles(_folder.Path, "*.tmp", SearchOption.AllDirectories).ShouldBeEmpty();
    }

    [TestMethod]
    public async Task Lookup_DownloadFails_IsUnavailableAndTheNextLookupTriesAgain()
    {
        bool failing = true;
        _server.Intercept = (_, _) => failing ? FakeRangeServer.CreateResponse(HttpStatusCode.InternalServerError) : null;

        RangeFetcher fetcher = CreateFetcher();
        RangeEntry entry = _server.GetEntries(9)[0];

        (await fetcher.LookupAsync(entry.GetHash(9))).Status.ShouldBe(RangeLookupStatus.Unavailable);

        _server.GetRequestCount(9).ShouldBe(3);
        fetcher.Failures.ShouldBe(1);
        fetcher.Downloads.ShouldBe(0);
        File.Exists(_store.GetRangePath(9)).ShouldBeFalse();
        _logger.Entries.ShouldContain(e =>
            e.Level == LogLevel.Warning && e.Message == "Range 00009 couldn't be downloaded on demand: HTTP 500 Internal Server Error");

        failing = false;

        (await fetcher.LookupAsync(entry.GetHash(9))).ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, entry.Count));

        // The range is stored after the lookup is answered, so this waits for it rather than have it written after the folder is deleted.
        await WaitUntilIdleAsync(fetcher);

        fetcher.Downloads.ShouldBe(1);
        _store.IsStored(9).ShouldBeTrue();
    }

    [TestMethod]
    public async Task Lookup_DownloadTimesOut_IsUnavailable()
    {
        _server.BeforeResponse = (_, cancellationToken) => Task.Delay(Timeout.Infinite, cancellationToken);

        RangeFetcher fetcher = CreateFetcher(timeout: TimeSpan.FromMilliseconds(300));
        var stopwatch = Stopwatch.StartNew();

        (await fetcher.LookupAsync(_server.GetEntries(4)[0].GetHash(4))).Status.ShouldBe(RangeLookupStatus.Unavailable);

        stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(5));
        fetcher.Failures.ShouldBe(1);
        _logger.Count("Range 00004 couldn't be downloaded on demand: The download timed out after 0.3 seconds.").ShouldBe(1);
        await WaitUntilIdleAsync(fetcher);
    }

    [TestMethod]
    public async Task Lookup_CallerStopsWaiting_DownloadContinuesAndIsStored()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _server.BeforeResponse = (_, cancellationToken) => release.Task.WaitAsync(cancellationToken);

        RangeFetcher fetcher = CreateFetcher();
        RangeEntry entry = _server.GetEntries(6)[0];
        using var cts = new CancellationTokenSource();

        Task<RangeLookupResult> lookup = fetcher.LookupAsync(entry.GetHash(6), cts.Token).AsTask();
        await WaitUntilAsync(() => _server.GetRequestCount(6) is 1);

        // Like a client that disconnects while its request waits for the download.
        await cts.CancelAsync();
        await Should.ThrowAsync<OperationCanceledException>(() => lookup);

        release.SetResult();
        await WaitUntilIdleAsync(fetcher);

        fetcher.Downloads.ShouldBe(1);
        fetcher.Failures.ShouldBe(0);
        _store.IsStored(6).ShouldBeTrue();
        (await _store.LookupAsync(entry.GetHash(6))).ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, entry.Count));
    }

    [TestMethod]
    public async Task Lookup_WriteFails_IsStillAnsweredFromTheDownload()
    {
        // A file where the range's folder should be makes the write fail, like a full disk or a read-only folder.
        Directory.CreateDirectory(Path.Combine(_folder.Path, "ranges"));
        File.WriteAllBytes(Path.Combine(_folder.Path, "ranges", "000"), []);

        RangeFetcher fetcher = CreateFetcher();
        RangeEntry[] entries = _server.GetEntries(2);

        (await fetcher.LookupAsync(entries[0].GetHash(2))).ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, entries[0].Count));
        await WaitUntilIdleAsync(fetcher);

        fetcher.Downloads.ShouldBe(1);
        fetcher.Failures.ShouldBe(0);
        _store.IsStored(2).ShouldBeFalse();
        _logger.Entries.ShouldContain(e =>
            e.Level == LogLevel.Warning && e.Message.StartsWith("Range 00002 was downloaded on demand but couldn't be stored.") && e.Exception is IOException);

        // It isn't stored, so the next lookup downloads it again.
        (await fetcher.LookupAsync(entries[1].GetHash(2))).ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, entries[1].Count));
        await WaitUntilIdleAsync(fetcher);

        _server.GetRequestCount(2).ShouldBe(2);
        Directory.GetFiles(_folder.Path, "*.tmp", SearchOption.AllDirectories).ShouldBeEmpty();
    }

    [TestMethod]
    public async Task Lookup_LimitsConcurrentDownloads()
    {
        var gate = new Lock();
        int active = 0;
        int peak = 0;

        _server.BeforeResponse = async (_, cancellationToken) => {
            lock (gate)
                peak = Math.Max(peak, ++active);

            await Task.Delay(50, cancellationToken);

            lock (gate)
                active--;
        };

        RangeFetcher fetcher = CreateFetcher(maxConcurrentDownloads: 2);

        RangeLookupResult[] results = await Task.WhenAll(
            Enumerable.Range(10, 8).Select(p => Task.Run(() => fetcher.LookupAsync(_server.GetEntries(p)[0].GetHash(p)).AsTask())));

        results.ShouldAllBe(r => r.Status == RangeLookupStatus.Found);
        _server.Requests.Count.ShouldBe(8);
        peak.ShouldBe(2);
        await WaitUntilIdleAsync(fetcher);
    }

    [TestMethod]
    public async Task Lookup_PrefixBeyondPrefixCount_IsUnavailableWithoutDownloading()
    {
        RangeFetcher fetcher = CreateFetcher();

        (await fetcher.LookupAsync(_server.GetEntries(0)[0].GetHash(PrefixCount))).Status.ShouldBe(RangeLookupStatus.Unavailable);

        _server.Requests.ShouldBeEmpty();
    }

    [TestMethod]
    public async Task DownloadFailures_AreLoggedAtMostOncePerInterval()
    {
        // Not retried, and the fake clock only drives the log interval.
        _server.Intercept = (_, _) => FakeRangeServer.CreateResponse(HttpStatusCode.NotFound);
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        RangeFetcher fetcher = CreateFetcher(time: time);

        for (int prefix = 0; prefix < 4; prefix++)
            (await fetcher.LookupAsync(_server.GetEntries(prefix)[0].GetHash(prefix))).Status.ShouldBe(RangeLookupStatus.Unavailable);

        fetcher.Failures.ShouldBe(4);
        _logger.Count("couldn't be downloaded on demand").ShouldBe(1);

        time.Advance(TimeSpan.FromMinutes(1));
        (await fetcher.LookupAsync(_server.GetEntries(4)[0].GetHash(4))).Status.ShouldBe(RangeLookupStatus.Unavailable);

        _logger.Count("couldn't be downloaded on demand").ShouldBe(2);
        _logger.Count("3 more on-demand range downloads failed and weren't logged.").ShouldBe(1);
    }

    [TestMethod]
    public async Task SyncAndOnDemandDownloadsOfTheSameRanges_LeaveValidFiles()
    {
        // Another instance syncs the shared folder while this one downloads the same ranges on demand. Requests for the first ranges are held until
        // both have arrived, so both writes race.
        const int Raced = 8;
        var arrivals = new ConcurrentDictionary<int, int>();
        var bothArrived = Enumerable.Range(0, Raced).ToDictionary(p => p, _ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));

        _server.BeforeResponse = async (prefix, cancellationToken) => {
            if (bothArrived.TryGetValue(prefix, out TaskCompletionSource? tcs))
            {
                if (arrivals.AddOrUpdate(prefix, 1, (_, n) => n + 1) >= 2)
                    tcs.TrySetResult();

                await tcs.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            }
        };

        RangeFetcher fetcher = CreateFetcher();
        Task<RangeLookupResult>[] lookups = [.. Enumerable.Range(0, PrefixCount)
            .Select(p => Task.Run(() => fetcher.LookupAsync(_server.GetEntries(p)[p % 50].GetHash(p)).AsTask()))];

        var syncStore = new RangeStore(_folder.Path, PrefixCount, _logger);
        RangeSyncResult syncResult = await CreateSynchronizer(syncStore).RunPassAsync(RangeSyncPassKind.Full);
        RangeLookupResult[] results = await Task.WhenAll(lookups);
        await WaitUntilIdleAsync(fetcher);

        syncResult.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        syncResult.RangesFailed.ShouldBe(0);
        results.ShouldAllBe(r => r.Status == RangeLookupStatus.Found);
        fetcher.Failures.ShouldBe(0);

        for (int prefix = 0; prefix < Raced; prefix++)
            _server.GetRequestCount(prefix).ShouldBe(2);

        var restarted = new RangeStore(_folder.Path, PrefixCount);

        for (int prefix = 0; prefix < PrefixCount; prefix++)
        {
            restarted.ReadHeader(prefix, out string? etag, out _, checkRecords: true).ShouldBe(RangeFileStatus.Valid);
            etag.ShouldBe(_server.GetETag(prefix));

            foreach (RangeEntry entry in _server.GetEntries(prefix).Where((_, i) => i % 10 is 0))
                (await restarted.LookupAsync(entry.GetHash(prefix))).ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, entry.Count));
        }

        Directory.GetFiles(_folder.Path, "*.tmp", SearchOption.AllDirectories).ShouldBeEmpty();
    }

    [TestMethod]
    public void InvalidOptions_Throw()
    {
        using var client = new HttpClient(_server, disposeHandler: false);

        Should.Throw<ArgumentOutOfRangeException>(() => new RangeFetcher(_store, client, options: new() { MaxConcurrentDownloads = 0 }));
        Should.Throw<ArgumentOutOfRangeException>(() => new RangeFetcher(_store, client, options: new() { Timeout = TimeSpan.Zero }));
    }

    private static RangeEntry GetAbsentEntry(RangeEntry[] entries)
    {
        var present = entries.Select(e => e.SuffixHex).ToHashSet();
        return entries.Select(e => new RangeEntry([.. e.Suffix[..^1], (byte)(e.Suffix[^1] ^ 1)], 1)).First(e => !present.Contains(e.SuffixHex));
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (int i = 0; i < 1000 && !condition(); i++)
            await Task.Delay(10);

        condition().ShouldBeTrue("Timed out waiting for the condition.");
    }

    // Waits until downloaded ranges are written (or failed to be).
    private static Task WaitUntilIdleAsync(RangeFetcher fetcher) => WaitUntilAsync(() => fetcher.ActiveFetches is 0);

    private RangeFetcher CreateFetcher(
        int maxConcurrentDownloads = RangeFetchOptions.DefaultMaxConcurrentDownloads, TimeSpan? timeout = null, TimeProvider? time = null)
    {
        var client = new HttpClient(_server, disposeHandler: false);
        RangeHttpClient.Configure(client, "Singulink.Cryptography.Pwned.Service.Tests");

        var options = new RangeFetchOptions {
            MaxConcurrentDownloads = maxConcurrentDownloads,
            Timeout = timeout ?? TimeSpan.FromSeconds(10),
            RetryDelay = TimeSpan.FromMilliseconds(1),
            TimeProvider = time ?? TimeProvider.System,
        };

        return new RangeFetcher(_store, client, _logger, options);
    }

    private RangeSynchronizer CreateSynchronizer(RangeStore store)
    {
        var client = new HttpClient(_server, disposeHandler: false);
        RangeHttpClient.Configure(client, "Singulink.Cryptography.Pwned.Service.Tests");

        var options = new RangeSyncOptions {
            DownloadConcurrency = 4,
            MaxAttempts = 3,
            RetryDelay = TimeSpan.FromMilliseconds(1),
            ProgressInterval = TimeSpan.FromHours(1),
        };

        return new RangeSynchronizer(store, client, _logger, options);
    }
}
