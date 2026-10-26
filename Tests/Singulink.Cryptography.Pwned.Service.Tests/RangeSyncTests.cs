using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace Singulink.Cryptography.Pwned.Service.Tests;

[TestClass]
public sealed class RangeSyncTests : IDisposable
{
    private const int PrefixCount = 300;

    private readonly TempFolder _folder = new();
    private readonly FakeRangeServer _server = new(PrefixCount);
    private readonly FakeLogger _logger = new();

    public void Dispose()
    {
        _server.Dispose();
        _folder.Dispose();
    }

    [TestMethod]
    public async Task FullPass_EmptyFolder_DownloadsEveryRange()
    {
        RangeStore store = CreateStore();

        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        result.RangesChecked.ShouldBe(PrefixCount);
        result.RangesUpdated.ShouldBe(PrefixCount);
        result.RangesFailed.ShouldBe(0);
        result.BytesDownloaded.ShouldBeGreaterThan(0);
        store.StoredRanges.ShouldBe(PrefixCount);

        _server.Requests.Count.ShouldBe(PrefixCount);
        _server.Requests.ShouldAllBe(r => r.IfNoneMatch == null && r.UserAgent.Contains("github.com/Singulink") && r.Version == HttpVersion.Version20);

        for (int prefix = 0; prefix < PrefixCount; prefix++)
        {
            store.ReadHeader(prefix, out string? etag, out _).ShouldBe(RangeFileStatus.Valid);
            etag.ShouldBe(_server.GetETag(prefix));
        }

        await ShouldMatchServerAsync(store, 0, 1, 255, 256, 299);

        RangeSyncState state = store.ReadSyncState();
        state.LastPassStarted.ShouldNotBeNull();
        state.LastPassCompleted.ShouldNotBeNull();
        state.CurrentPassStarted.ShouldBeNull();

        Directory.GetFiles(_folder.Path, "*.tmp", SearchOption.AllDirectories).ShouldBeEmpty();
    }

    [TestMethod]
    public async Task FullPass_Unchanged_SendsIfNoneMatchAndWritesNothing()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        var writeTimes = Enumerable.Range(0, PrefixCount).ToDictionary(p => p, p => File.GetLastWriteTimeUtc(store.GetRangePath(p)));
        DateTimeOffset firstPassStarted = store.ReadSyncState().LastPassStarted!.Value;
        _server.ClearRequests();

        RangeSyncResult result = await CreateSynchronizer(CreateStore()).RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        result.RangesChecked.ShouldBe(PrefixCount);
        result.RangesUpdated.ShouldBe(0);
        result.BytesDownloaded.ShouldBe(0);

        _server.Requests.Count.ShouldBe(PrefixCount);
        _server.Requests.ShouldAllBe(r => r.IfNoneMatch == _server.GetETag(r.Prefix));

        foreach ((int prefix, DateTime writeTime) in writeTimes)
            File.GetLastWriteTimeUtc(store.GetRangePath(prefix)).ShouldBe(writeTime);

        store.ReadSyncState().LastPassStarted!.Value.ShouldBeGreaterThan(firstPassStarted);
    }

    [TestMethod]
    public async Task FullPass_ChangedRange_IsReplaced()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        RangeEntry[] oldEntries = _server.GetEntries(5);
        _server.SetRange(5, TestRanges.Generate(new Random(12345), 120));

        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.RangesUpdated.ShouldBe(1);
        store.ReadHeader(5, out string? etag, out _).ShouldBe(RangeFileStatus.Valid);
        etag.ShouldBe(_server.GetETag(5));

        await ShouldMatchServerAsync(store, 5);
        (await store.LookupAsync(oldEntries[0].GetHash(5))).Status.ShouldBe(RangeLookupStatus.NotFound);
    }

    [TestMethod]
    public async Task FullPass_TransientFailures_AreRetried()
    {
        _server.Intercept = (prefix, number) => (prefix, number) switch {
            (3, <= 2) => FakeRangeServer.CreateResponse(HttpStatusCode.InternalServerError),
            (4, 1) => CreateTooManyRequests(),
            (5, 1) => throw new HttpRequestException("Connection reset."),
            (6, 1) => throw new TaskCanceledException("Simulated timeout."),
            (7, 1) => FakeRangeServer.CreateResponse(HttpStatusCode.OK, "not a range"),
            (8, 1) => FakeRangeServer.CreateResponse(HttpStatusCode.RequestTimeout),
            _ => null,
        };

        RangeStore store = CreateStore();
        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        result.RangesFailed.ShouldBe(0);
        store.StoredRanges.ShouldBe(PrefixCount);

        _server.GetRequestCount(3).ShouldBe(3);
        _server.GetRequestCount(4).ShouldBe(2);
        _server.GetRequestCount(5).ShouldBe(2);
        _server.GetRequestCount(6).ShouldBe(2);
        _server.GetRequestCount(7).ShouldBe(2);
        _server.GetRequestCount(8).ShouldBe(2);
        _server.GetRequestCount(9).ShouldBe(1);

        await ShouldMatchServerAsync(store, 3, 4, 5, 6, 7, 8);

        static HttpResponseMessage CreateTooManyRequests()
        {
            HttpResponseMessage response = FakeRangeServer.CreateResponse(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero);
            return response;
        }
    }

    [TestMethod]
    public async Task FullPass_PermanentFailure_IsNotRetriedAndRetryPassFetchesItLater()
    {
        _server.Intercept = (prefix, _) => prefix is 9 ? FakeRangeServer.CreateResponse(HttpStatusCode.NotFound) : null;

        RangeStore store = CreateStore();
        RangeSynchronizer synchronizer = CreateSynchronizer(store);
        RangeSyncResult result = await synchronizer.RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        result.RangesFailed.ShouldBe(1);
        _server.GetRequestCount(9).ShouldBe(1);
        store.StoredRanges.ShouldBe(PrefixCount - 1);
        _logger.Entries.ShouldContain(e => e.Level == LogLevel.Warning && e.Message.Contains("Range 00009 failed: HTTP 404"));

        _server.Intercept = null;
        _server.ClearRequests();

        result = await synchronizer.RunPassAsync(RangeSyncPassKind.Retry);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        result.RangesUpdated.ShouldBe(1);
        _server.Requests.ShouldHaveSingleItem().Prefix.ShouldBe(9);
        store.StoredRanges.ShouldBe(PrefixCount);
    }

    [TestMethod]
    public async Task FullPass_ConsecutiveFailures_AbortAndResume()
    {
        // Ranges from 100 on fail, so the pass aborts there and resumes from the first range that didn't succeed.

        bool unreachable = true;
        _server.Intercept = (prefix, _) => unreachable && prefix >= 100 ? throw new HttpRequestException("No such host is known.") : null;

        RangeStore store = CreateStore();
        RangeSyncResult result = await CreateSynchronizer(store, concurrency: 1, maxConsecutiveFailures: 5).RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Aborted);
        result.RangesUpdated.ShouldBe(100);
        result.RangesFailed.ShouldBe(5);
        _server.Requests.Max(r => r.Prefix).ShouldBe(104);

        RangeSyncState state = store.ReadSyncState();
        DateTimeOffset started = state.CurrentPassStarted!.Value;
        state.CurrentPassPosition.ShouldBe(100);
        state.LastPassCompleted.ShouldBeNull();

        unreachable = false;
        _server.ClearRequests();

        result = await CreateSynchronizer(CreateStore(), concurrency: 4).RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        result.RangesChecked.ShouldBe(PrefixCount - 100);
        _server.Requests.Min(r => r.Prefix).ShouldBe(100);
        _server.Requests.Count.ShouldBe(PrefixCount - 100);

        state = store.ReadSyncState();
        state.LastPassStarted.ShouldBe(started);
        state.LastPassCompleted.ShouldNotBeNull();
        state.CurrentPassStarted.ShouldBeNull();
    }

    [TestMethod]
    public async Task FullPass_Unreachable_AbortsQuickly()
    {
        _server.Intercept = (_, _) => FakeRangeServer.CreateResponse(HttpStatusCode.ServiceUnavailable);

        RangeStore store = CreateStore();
        RangeSyncResult result = await CreateSynchronizer(store, concurrency: 4, maxConsecutiveFailures: 10).RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Aborted);
        result.RangesUpdated.ShouldBe(0);
        _server.Requests.Count.ShouldBeLessThan(60);
        store.ReadSyncState().CurrentPassPosition.ShouldBe(0);
        _logger.Entries.ShouldContain(e => e.Level == LogLevel.Warning && e.Message.Contains("aborted"));
    }

    [TestMethod]
    public async Task Pass_LockHeld_IsSkipped()
    {
        RangeStore store = CreateStore();

        using (SyncLock.TryAcquire(_folder.Path).ShouldNotBeNull())
        {
            RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

            result.Outcome.ShouldBe(RangeSyncOutcome.LockHeld);
            SyncLock.TryAcquire(_folder.Path).ShouldBeNull();
        }

        _server.Requests.ShouldBeEmpty();
        store.ReadSyncState().CurrentPassStarted.ShouldBeNull();
    }

    [TestMethod]
    public async Task Pass_LockFileOpenedByAnotherHandle_IsSkipped()
    {
        Directory.CreateDirectory(_folder.Path);

        using (new FileStream(Path.Combine(_folder.Path, SyncLock.FileName), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            RangeSyncResult result = await CreateSynchronizer(CreateStore()).RunPassAsync(RangeSyncPassKind.Retry);
            result.Outcome.ShouldBe(RangeSyncOutcome.LockHeld);
        }

        (await CreateSynchronizer(CreateStore()).RunPassAsync(RangeSyncPassKind.Retry)).Outcome.ShouldBe(RangeSyncOutcome.Completed);
    }

    [TestMethod]
    public async Task Pass_DeletesStrayTempFiles()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        string[] tempFiles = [
            store.GetRangePath(5) + ".0123456789abcdef0123456789abcdef.tmp",
            store.GetRangePath(260) + ".fedcba9876543210fedcba9876543210.tmp",
            Path.Combine(_folder.Path, RangeStore.SyncStateFileName + ".00112233445566778899aabbccddeeff.tmp"),
        ];

        // Other files that end in .tmp aren't touched.
        string[] otherFiles = [
            Path.Combine(_folder.Path, "notes.tmp"),
            Path.Combine(_folder.Path, "ranges", "notes.tmp"),
            Path.Combine(_folder.Path, "ranges", "000", "notes.tmp"),
            store.GetRangePath(5) + ".tmp",
            store.GetRangePath(5) + ".AAAABBBBCCCCDDDDEEEEFFFF00001111.tmp",
        ];

        foreach (string file in tempFiles.Concat(otherFiles))
            WriteOldFile(file);

        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Retry);

        tempFiles.ShouldAllBe(f => !File.Exists(f));
        otherFiles.ShouldAllBe(f => File.Exists(f));
        File.Exists(store.GetRangePath(5)).ShouldBeTrue();
        _logger.Count("Deleted 3 temp files").ShouldBe(1);
    }

    [TestMethod]
    public async Task Pass_KeepsRecentTempFiles()
    {
        // Another process (e.g. an instance downloading a range on demand, which doesn't hold the sync lock) may be writing a recent temp file.
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        string fresh = store.GetRangePath(5) + ".0123456789abcdef0123456789abcdef.tmp";
        string almostOld = store.GetRangePath(6) + ".0123456789abcdef0123456789abcdef.tmp";
        string old = store.GetRangePath(7) + ".0123456789abcdef0123456789abcdef.tmp";

        File.WriteAllBytes(fresh, [1, 2, 3]);
        File.WriteAllBytes(almostOld, [1, 2, 3]);
        File.SetLastWriteTimeUtc(almostOld, DateTime.UtcNow - RangeStore.TempFileMinAge + TimeSpan.FromMinutes(1));
        WriteOldFile(old);

        store.DeleteTempFiles().ShouldBe(1);
        File.Exists(fresh).ShouldBeTrue();
        File.Exists(almostOld).ShouldBeTrue();
        File.Exists(old).ShouldBeFalse();

        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Retry);
        File.Exists(fresh).ShouldBeTrue();
    }

    [TestMethod]
    public async Task FullPass_InvalidHeader_IsDownloadedAgain()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        byte[] bytes = File.ReadAllBytes(store.GetRangePath(2));
        bytes[0] = 0;
        File.WriteAllBytes(store.GetRangePath(2), bytes);
        store.ReadHeader(2, out _, out _).ShouldBe(RangeFileStatus.Invalid);
        _server.ClearRequests();

        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.RangesUpdated.ShouldBe(1);
        _server.Requests.Single(r => r.Prefix is 2).IfNoneMatch.ShouldBeNull();
        store.ReadHeader(2, out _, out _).ShouldBe(RangeFileStatus.Valid);
    }

    [TestMethod]
    public async Task RetryPass_InvalidHeader_IsDownloadedAgain()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        // A truncated file isn't counted by the scan, so a missing pass picks it up.
        string path = store.GetRangePath(7);
        File.WriteAllBytes(path, File.ReadAllBytes(path)[..100]);
        _server.ClearRequests();

        RangeStore restarted = CreateStore();
        RangeSyncResult result = await CreateSynchronizer(restarted).RunPassAsync(RangeSyncPassKind.Retry);

        result.RangesUpdated.ShouldBe(1);
        _server.Requests.ShouldHaveSingleItem().Prefix.ShouldBe(7);
        restarted.StoredRanges.ShouldBe(PrefixCount);
        await ShouldMatchServerAsync(restarted, 7);
    }

    [TestMethod]
    public async Task FullPass_MalformedResponse_KeepsExistingFile()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        byte[] before = File.ReadAllBytes(store.GetRangePath(3));
        RangeEntry[] entries = _server.GetEntries(3);
        string unsorted = TestRanges.ToResponse(entries.Reverse());
        _server.Intercept = (prefix, _) => prefix is 3 ? FakeRangeServer.CreateResponse(HttpStatusCode.OK, unsorted) : null;

        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        result.RangesFailed.ShouldBe(1);
        File.ReadAllBytes(store.GetRangePath(3)).ShouldBe(before);
        store.StoredRanges.ShouldBe(PrefixCount);
        _logger.Entries.ShouldContain(e => e.Message.Contains("Range 00003 failed") && e.Message.Contains("sorted"));
    }

    [TestMethod]
    public async Task RetryPass_OnlyDownloadsMissingRanges()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        File.Delete(store.GetRangePath(10));
        File.Delete(store.GetRangePath(270));
        _server.ClearRequests();

        RangeStore restarted = CreateStore();
        RangeSyncResult result = await CreateSynchronizer(restarted).RunPassAsync(RangeSyncPassKind.Retry);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        result.RangesUpdated.ShouldBe(2);
        _server.Requests.Select(r => r.Prefix).Order().ShouldBe([10, 270]);
        restarted.StoredRanges.ShouldBe(PrefixCount);
    }

    [TestMethod]
    public async Task RetryPass_RangeStoredByAnotherProcess_IsNotDownloaded()
    {
        RangeStore store = CreateStore();
        await store.ScanAsync();
        store.StoredRanges.ShouldBe(0);

        // Another process stores every range after this one scanned.
        await CreateSynchronizer(CreateStore()).RunPassAsync(RangeSyncPassKind.Full);
        _server.ClearRequests();

        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Retry);

        result.RangesUpdated.ShouldBe(0);
        _server.Requests.ShouldBeEmpty();
        store.StoredRanges.ShouldBe(PrefixCount);
    }

    [TestMethod]
    public async Task FullPass_Canceled_SavesPositionAndResumes()
    {
        using var cts = new CancellationTokenSource();
        _server.OnRequest = prefix => {
            if (prefix is 150)
                cts.Cancel();
        };

        RangeStore store = CreateStore();
        RangeSyncResult result = await CreateSynchronizer(store, concurrency: 1).RunPassAsync(RangeSyncPassKind.Full, cts.Token);

        result.Outcome.ShouldBe(RangeSyncOutcome.Canceled);
        store.ReadSyncState().CurrentPassPosition.ShouldBe(150);

        _server.OnRequest = null;
        _server.ClearRequests();

        result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        _server.Requests.Min(r => r.Prefix).ShouldBe(150);
        store.StoredRanges.ShouldBe(PrefixCount);
    }

    [TestMethod]
    public async Task FullPass_ReportsProgress()
    {
        var gate = new ManualResetEventSlim();
        _server.OnRequest = prefix => {
            if (prefix is 200)
                gate.Wait(TimeSpan.FromSeconds(10));
        };

        RangeStore store = CreateStore();
        RangeSynchronizer synchronizer = CreateSynchronizer(store, concurrency: 1, progressInterval: TimeSpan.FromMilliseconds(20));
        synchronizer.CurrentPass.ShouldBeNull();

        Task<RangeSyncResult> passTask = synchronizer.RunPassAsync(RangeSyncPassKind.Full);

        RangeSyncProgress? progress = null;

        for (int i = 0; i < 500 && progress?.RangesChecked is not 200; i++)
        {
            await Task.Delay(10);
            progress = synchronizer.CurrentPass;
        }

        progress.ShouldNotBeNull();
        progress.Kind.ShouldBe(RangeSyncPassKind.Full);
        progress.RangesTotal.ShouldBe(PrefixCount);
        progress.RangesChecked.ShouldBe(200);
        progress.RangesUpdated.ShouldBe(200);

        // The position is saved with the progress.
        for (int i = 0; i < 500 && store.ReadSyncState().CurrentPassPosition is not 200; i++)
            await Task.Delay(10);

        store.ReadSyncState().CurrentPassPosition.ShouldBe(200);

        gate.Set();
        (await passTask).Outcome.ShouldBe(RangeSyncOutcome.Completed);

        synchronizer.CurrentPass.ShouldBeNull();
        _logger.Entries.ShouldContain(e => e.Message.Contains("Sync pass progress"));
    }

    [TestMethod]
    public void RetryAfter_DeltaAndDate_AreHonored()
    {
        var now = new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.Zero);

        RangeDownloader.GetRetryAfter(new RetryConditionHeaderValue(TimeSpan.FromSeconds(7)), now).ShouldBe(TimeSpan.FromSeconds(7));
        RangeDownloader.GetRetryAfter(new RetryConditionHeaderValue(now.AddSeconds(30)), now).ShouldBe(TimeSpan.FromSeconds(30));
        RangeDownloader.GetRetryAfter(new RetryConditionHeaderValue(now.AddSeconds(-30)), now).ShouldBe(TimeSpan.Zero);
        RangeDownloader.GetRetryAfter(null, now).ShouldBeNull();

        var downloader = new RangeDownloader(new HttpClient(), new RangeSyncOptions { RetryDelay = TimeSpan.FromSeconds(1) });

        downloader.GetRetryDelay(1, TimeSpan.FromSeconds(7)).ShouldBe(TimeSpan.FromSeconds(7));
        downloader.GetRetryDelay(1, TimeSpan.FromHours(1)).ShouldBe(TimeSpan.FromMinutes(5));
        downloader.GetRetryDelay(1, null).ShouldBeInRange(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1.25));
        downloader.GetRetryDelay(3, null).ShouldBeInRange(TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(5));
        downloader.GetRetryDelay(20, null).ShouldBeInRange(TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1.25));
    }

    [TestMethod]
    public async Task FullPass_WithContentMd5_AcceptsRanges()
    {
        _server.SendContentMd5 = true;
        RangeStore store = CreateStore();

        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.RangesUpdated.ShouldBe(PrefixCount);
        result.RangesFailed.ShouldBe(0);
    }

    [TestMethod]
    public async Task FullPass_ContentMd5Mismatch_FailsRange()
    {
        RangeEntry[] entries = _server.GetEntries(4);
        byte[] md5 = FakeRangeServer.GetMd5(TestRanges.ToResponse(entries));
        string truncated = TestRanges.ToResponse(entries.Take(60));

        _server.Intercept = (prefix, _) => {
            if (prefix is not 4)
                return null;

            HttpResponseMessage response = FakeRangeServer.CreateResponse(HttpStatusCode.OK, truncated);
            response.Content.Headers.ContentMD5 = md5;
            return response;
        };

        RangeStore store = CreateStore();
        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.RangesFailed.ShouldBe(1);
        _server.GetRequestCount(4).ShouldBe(3);
        File.Exists(store.GetRangePath(4)).ShouldBeFalse();
        _logger.Entries.ShouldContain(e => e.Level == LogLevel.Warning && e.Message.Contains("Range 00004 failed") && e.Message.Contains("Content-MD5"));
    }

    [TestMethod]
    public async Task FullPass_ShrunkenResponseWithoutMd5_KeepsStoredRange()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);
        byte[] before = File.ReadAllBytes(store.GetRangePath(6));

        // The range changed (new ETag) but the response was cut short at a line boundary.
        _server.SetRange(6, [.. _server.GetEntries(6).Take(70)]);

        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.RangesFailed.ShouldBe(1);
        File.ReadAllBytes(store.GetRangePath(6)).ShouldBe(before);
        store.ReadSyncState().FailedPrefixes.ShouldBe([6]);
        _logger.Entries.ShouldContain(e => e.Level == LogLevel.Warning && e.Message.Contains("Range 00006 failed") && e.Message.Contains("fewer than the 100"));
    }

    [TestMethod]
    public async Task FullPass_ShrunkenResponseWithMatchingMd5_IsAccepted()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        _server.SendContentMd5 = true;
        _server.SetRange(6, [.. _server.GetEntries(6).Take(70)]);

        RangeSyncResult result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.RangesUpdated.ShouldBe(1);
        result.RangesFailed.ShouldBe(0);
        await ShouldMatchServerAsync(store, 6);
    }

    [TestMethod]
    public async Task FullPass_FailedStoredRange_IsRecordedAndRetryPassChecksItAgain()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        // Range 3 changed but fails; range 4 is missing and fails.
        string oldETag = _server.GetETag(3);
        _server.SetRange(3, TestRanges.Generate(new Random(99), 150));
        File.Delete(store.GetRangePath(4));
        _server.Intercept = (prefix, _) => prefix is 3 or 4 ? FakeRangeServer.CreateResponse(HttpStatusCode.InternalServerError) : null;

        RangeStore restarted = CreateStore();
        RangeSyncResult result = await CreateSynchronizer(restarted).RunPassAsync(RangeSyncPassKind.Full);

        result.Outcome.ShouldBe(RangeSyncOutcome.Completed);
        result.RangesFailed.ShouldBe(2);

        // Missing ranges are retried anyway, so only the stored range that may be out of date is recorded.
        restarted.ReadSyncState().FailedPrefixes.ShouldBe([3]);

        _server.Intercept = null;
        _server.ClearRequests();

        result = await CreateSynchronizer(restarted).RunPassAsync(RangeSyncPassKind.Retry);

        result.RangesUpdated.ShouldBe(2);
        _server.Requests.OrderBy(r => r.Prefix).Select(r => r.Prefix).ShouldBe([3, 4]);
        _server.Requests.Single(r => r.Prefix is 3).IfNoneMatch.ShouldBe(oldETag);
        _server.Requests.Single(r => r.Prefix is 4).IfNoneMatch.ShouldBeNull();
        restarted.ReadSyncState().FailedPrefixes.ShouldBeNull();
        await ShouldMatchServerAsync(restarted, 3, 4);
    }

    [TestMethod]
    public async Task FullPass_HeaderReadError_FailsRangeWithoutDownloadingOrUnmarking()
    {
        RangeStore store = CreateStore();
        await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);
        _server.ClearRequests();

        RangeSyncResult result;

        using (new FileStream(store.GetRangePath(8), FileMode.Open, FileAccess.Read, FileShare.None))
            result = await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full);

        result.RangesFailed.ShouldBe(1);
        _server.Requests.ShouldNotContain(r => r.Prefix == 8);
        store.IsStored(8).ShouldBeTrue();
        store.ReadSyncState().FailedPrefixes.ShouldBe([8]);
    }

    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    public async Task FullPass_FinalStateSaveFails_CountsAsAborted()
    {
        // Hold the state file open without sharing delete access from the first request on, so saving it at the end fails.
        string statePath = Path.Combine(_folder.Path, RangeStore.SyncStateFileName);
        FileStream? held = null;
        _server.OnRequest = _ => held ??= new FileStream(statePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        RangeStore store = CreateStore();
        RangeSyncResult result;

        try
        {
            result = await CreateSynchronizer(store, concurrency: 1).RunPassAsync(RangeSyncPassKind.Full);
        }
        finally
        {
            held?.Dispose();
        }

        result.Outcome.ShouldBe(RangeSyncOutcome.Aborted);
        store.ReadSyncState().CurrentPassStarted.ShouldNotBeNull();
        _logger.Entries.ShouldContain(e => e.Message.Contains("Could not save the sync state"));

        _server.OnRequest = null;

        (await CreateSynchronizer(store).RunPassAsync(RangeSyncPassKind.Full)).Outcome.ShouldBe(RangeSyncOutcome.Completed);
        store.ReadSyncState().CurrentPassStarted.ShouldBeNull();
    }

    [TestMethod]
    public async Task FullPass_LimitsConcurrentWrites()
    {
        RangeStore store = CreateStore();

        await CreateSynchronizer(store, concurrency: 32).RunPassAsync(RangeSyncPassKind.Full);

        store.PeakConcurrentWrites.ShouldBeInRange(1, RangeStore.MaxConcurrentWrites);
    }

    [TestMethod]
    public async Task FullPass_FailureLogIncludesException()
    {
        _server.Intercept = (prefix, _) => prefix is 2 ? throw new HttpRequestException("Connection reset.") : null;

        await CreateSynchronizer(CreateStore()).RunPassAsync(RangeSyncPassKind.Full);

        _logger.Entries.ShouldContain(e => e.Message.Contains("Range 00002 failed") && e.Exception is HttpRequestException);
    }

    [TestMethod]
    public async Task FullPass_UnexpectedError_StopsThePassAndThrows()
    {
        _server.Intercept = (_, _) => throw new InvalidOperationException("Something broke.");
        RangeStore store = CreateStore();

        await Should.ThrowAsync<InvalidOperationException>(() => CreateSynchronizer(store, concurrency: 4).RunPassAsync(RangeSyncPassKind.Full));

        _server.Requests.Count.ShouldBeLessThanOrEqualTo(8);
        store.ReadSyncState().CurrentPassStarted.ShouldNotBeNull();
    }

    [TestMethod]
    public void SyncLock_OnlyLockContentionCountsAsHeld()
    {
        SyncLock.IsSharingViolation(new IOException("There is not enough space on the disk.", unchecked((int)0x80070070))).ShouldBeFalse();
        SyncLock.IsSharingViolation(new IOException("Read-only file system", 30)).ShouldBeFalse();
        SyncLock.IsSharingViolation(new FileNotFoundException()).ShouldBeFalse();

        if (OperatingSystem.IsWindows())
        {
            SyncLock.IsSharingViolation(new IOException("Sharing violation", unchecked((int)0x80070020))).ShouldBeTrue();
            SyncLock.IsSharingViolation(new IOException("Lock violation", unchecked((int)0x80070021))).ShouldBeTrue();
        }
        else
        {
            SyncLock.IsSharingViolation(new IOException("Would block", OperatingSystem.IsLinux() ? 11 : 35)).ShouldBeTrue();
        }

        // The real thing.
        using (SyncLock.TryAcquire(_folder.Path).ShouldNotBeNull())
        {
            var ex = Should.Throw<IOException>(() => File.OpenHandle(Path.Combine(_folder.Path, SyncLock.FileName), FileMode.Open, FileAccess.ReadWrite));
            SyncLock.IsSharingViolation(ex).ShouldBeTrue();
        }
    }

    private static void WriteOldFile(string path)
    {
        File.WriteAllBytes(path, [1, 2, 3]);
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow - RangeStore.TempFileMinAge - TimeSpan.FromMinutes(1));
    }

    private RangeStore CreateStore() => new(_folder.Path, PrefixCount, _logger);

    private RangeSynchronizer CreateSynchronizer(
        RangeStore store, int concurrency = 4, int maxConsecutiveFailures = 0, TimeSpan? progressInterval = null)
    {
        var client = new HttpClient(_server, disposeHandler: false);
        RangeHttpClient.Configure(client, "Singulink.Cryptography.Pwned.Service.Tests");

        var options = new RangeSyncOptions {
            DownloadConcurrency = concurrency,
            MaxAttempts = 3,
            RetryDelay = TimeSpan.FromMilliseconds(1),
            MaxConsecutiveFailures = maxConsecutiveFailures,
            ProgressInterval = progressInterval ?? TimeSpan.FromHours(1),
        };

        return new RangeSynchronizer(store, client, _logger, options);
    }

    private async Task ShouldMatchServerAsync(RangeStore store, params int[] prefixes)
    {
        foreach (int prefix in prefixes)
        {
            foreach (RangeEntry entry in _server.GetEntries(prefix))
            {
                RangeLookupResult result = await store.LookupAsync(entry.GetHash(prefix));
                result.ShouldBe(new RangeLookupResult(RangeLookupStatus.Found, entry.Count));
            }
        }
    }
}
