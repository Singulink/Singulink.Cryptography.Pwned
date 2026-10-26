using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Singulink.Cryptography.Pwned.Service.Tests;

/// <summary>
/// Scheduling tests for the hosted sync service, with a fake clock.
/// </summary>
[TestClass]
public sealed class RangeSyncServiceTests : IAsyncDisposable
{
    private const int PrefixCount = 16;

    private static readonly DateTimeOffset T0 = new(2026, 10, 21, 0, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Week = TimeSpan.FromDays(7);
    private static readonly TimeSpan RetryInterval = TimeSpan.FromMinutes(15);

    private readonly TempFolder _folder = new();
    private readonly FakeRangeServer _server = new(PrefixCount);
    private readonly FakeTimeProvider _time = new(T0);
    private readonly FakeLogger _logger = new();
    private readonly ILoggerFactory _loggerFactory;
    private readonly SemaphoreSlim _waits = new(0);
    private readonly RangeStore _store;
    private RangeSyncService? _service;

    public RangeSyncServiceTests()
    {
        _loggerFactory = LoggerFactory.Create(builder => builder.AddProvider(new FakeLoggerProvider(_logger.Collector)));
        _store = new RangeStore(_folder.Path, PrefixCount, _logger);
    }

    public async ValueTask DisposeAsync()
    {
        if (_service is not null)
        {
            await _service.StopAsync(CancellationToken.None);
            _service.Dispose();
        }

        _loggerFactory.Dispose();
        _waits.Dispose();
        _server.Dispose();
        _folder.Dispose();
    }

    [TestMethod]
    public async Task EmptyFolder_RunsFullPassThenWeekly()
    {
        await StartAsync();

        (await WaitForIdleAsync()).ShouldBe(T0 + Week);
        _server.Requests.Count.ShouldBe(PrefixCount);
        _store.StoredRanges.ShouldBe(PrefixCount);

        _time.Advance(Week);

        (await WaitForIdleAsync()).ShouldBe(T0 + Week + Week);
        _server.Requests.Count.ShouldBe(PrefixCount * 2);
        _server.Requests.Skip(PrefixCount).ShouldAllBe(r => r.IfNoneMatch != null);
    }

    [TestMethod]
    public async Task LockHeld_RetriesEveryMinuteAndLogsOnce()
    {
        using (SyncLock.TryAcquire(_folder.Path).ShouldNotBeNull())
        {
            await StartAsync();

            (await WaitForIdleAsync()).ShouldBe(T0 + TimeSpan.FromMinutes(1));

            _time.Advance(TimeSpan.FromMinutes(1));

            (await WaitForIdleAsync()).ShouldBe(T0 + TimeSpan.FromMinutes(2));
            _logger.Count("Another process is syncing").ShouldBe(1);
            _server.Requests.ShouldBeEmpty();
        }

        _time.Advance(TimeSpan.FromMinutes(1));

        (await WaitForIdleAsync()).ShouldBe(T0 + TimeSpan.FromMinutes(2) + Week);
        _server.Requests.Count.ShouldBe(PrefixCount);
    }

    [TestMethod]
    public async Task AbortedPass_ResumesAfterRetryInterval()
    {
        bool unreachable = true;
        _server.Intercept = (_, _) => unreachable ? FakeRangeServer.CreateResponse(HttpStatusCode.ServiceUnavailable) : null;

        await StartAsync();

        (await WaitForIdleAsync()).ShouldBe(T0 + RetryInterval);
        _store.ReadSyncState().CurrentPassStarted.ShouldBe(T0);

        unreachable = false;
        _time.Advance(RetryInterval);

        // The resumed pass keeps its start time, so the next one is due a week after it.
        (await WaitForIdleAsync()).ShouldBe(T0 + Week);
        _store.StoredRanges.ShouldBe(PrefixCount);
        _store.ReadSyncState().LastPassStarted.ShouldBe(T0);
    }

    [TestMethod]
    public async Task MissingRangeAfterCompletedPass_IsRetriedAfterRetryInterval()
    {
        bool failing = true;
        _server.Intercept = (prefix, _) => failing && prefix is 5 ? FakeRangeServer.CreateResponse(HttpStatusCode.NotFound) : null;

        await StartAsync();

        (await WaitForIdleAsync()).ShouldBe(T0 + RetryInterval);
        _store.StoredRanges.ShouldBe(PrefixCount - 1);
        _store.ReadSyncState().LastPassCompleted.ShouldNotBeNull();

        failing = false;
        _server.ClearRequests();
        _time.Advance(RetryInterval);

        (await WaitForIdleAsync()).ShouldBe(T0 + Week);
        _server.Requests.ShouldHaveSingleItem().Prefix.ShouldBe(5);
        _store.StoredRanges.ShouldBe(PrefixCount);
    }

    [TestMethod]
    public async Task InterruptedPass_ResumesAtStartup()
    {
        var writer = new RangeStore(_folder.Path, PrefixCount);

        for (int prefix = 0; prefix < 8; prefix++)
            await TestRanges.WriteAsync(writer, prefix, _server.GetEntries(prefix), _server.GetETag(prefix));

        DateTimeOffset started = T0 - TimeSpan.FromHours(1);
        await writer.WriteSyncStateAsync(new() { CurrentPassStarted = started, CurrentPassPosition = 8 }, CancellationToken.None);

        await StartAsync();

        (await WaitForIdleAsync()).ShouldBe(started + Week);
        _server.Requests.Select(r => r.Prefix).Order().ShouldBe(Enumerable.Range(8, 8));
        _store.StoredRanges.ShouldBe(PrefixCount);
    }

    [TestMethod]
    public async Task MissingRangesAfterCompletedPass_AreDownloadedAtStartup()
    {
        var writer = new RangeStore(_folder.Path, PrefixCount);

        for (int prefix = 0; prefix < 8; prefix++)
            await TestRanges.WriteAsync(writer, prefix, _server.GetEntries(prefix), _server.GetETag(prefix));

        // The last full pass completed a day ago but left half the ranges missing (or they were deleted since).
        DateTimeOffset lastPass = T0 - TimeSpan.FromDays(1);
        await writer.WriteSyncStateAsync(new() { LastPassStarted = lastPass, LastPassCompleted = lastPass }, CancellationToken.None);

        await StartAsync();

        // A retry pass runs right away, without waiting for the retry interval or the weekly pass.
        (await WaitForIdleAsync()).ShouldBe(lastPass + Week);
        _server.Requests.Select(r => r.Prefix).Order().ShouldBe(Enumerable.Range(8, 8));
        _store.StoredRanges.ShouldBe(PrefixCount);
    }

    [TestMethod]
    public async Task FailedStoredRange_IsCheckedAgainAfterRetryInterval()
    {
        await StartAsync();
        (await WaitForIdleAsync()).ShouldBe(T0 + Week);

        string oldETag = _server.GetETag(3);
        RangeEntry[] newEntries = TestRanges.Generate(new Random(77), 150);
        _server.SetRange(3, newEntries);

        bool failing = true;
        _server.Intercept = (prefix, _) => failing && prefix is 3 ? FakeRangeServer.CreateResponse(HttpStatusCode.InternalServerError) : null;
        _time.Advance(Week);

        (await WaitForIdleAsync()).ShouldBe(T0 + Week + RetryInterval);
        _store.ReadSyncState().FailedPrefixes.ShouldBe([3]);

        failing = false;
        _server.ClearRequests();
        _time.Advance(RetryInterval);

        (await WaitForIdleAsync()).ShouldBe(T0 + Week + Week);
        _server.Requests.ShouldHaveSingleItem().ShouldSatisfyAllConditions(r => r.Prefix.ShouldBe(3), r => r.IfNoneMatch.ShouldBe(oldETag));
        _store.ReadSyncState().FailedPrefixes.ShouldBeNull();
        (await _store.LookupAsync(newEntries[0].GetHash(3))).Status.ShouldBe(RangeLookupStatus.Found);
    }

    [TestMethod]
    public async Task UnreadableSyncState_IsLoggedOnceAndRetriedAfterRetryInterval()
    {
        // A folder where the state file should be makes reading it throw.
        Directory.CreateDirectory(Path.Combine(_folder.Path, RangeStore.SyncStateFileName));

        await StartAsync();

        (await WaitForIdleAsync()).ShouldBe(T0 + RetryInterval);

        // No hot loop: the error isn't logged again until the retry interval has passed.
        await Task.Delay(300);
        _logger.Count("Range sync failed").ShouldBe(1);

        _time.Advance(RetryInterval);

        (await WaitForIdleAsync()).ShouldBe(T0 + RetryInterval + RetryInterval);
        _logger.Count("Range sync failed").ShouldBe(2);
        _server.Requests.ShouldBeEmpty();
    }

    [TestMethod]
    [DataRow(30)]
    [DataRow(-1)]
    public async Task LastPassInTheFuture_CountsAsNow(int daysAhead)
    {
        var writer = new RangeStore(_folder.Path, PrefixCount);

        for (int prefix = 0; prefix < PrefixCount; prefix++)
            await TestRanges.WriteAsync(writer, prefix, _server.GetEntries(prefix), _server.GetETag(prefix));

        // -1: as far in the future as possible, which would overflow when the interval is added.
        DateTimeOffset lastPass = daysAhead < 0 ? DateTimeOffset.MaxValue : T0.AddDays(daysAhead);
        await writer.WriteSyncStateAsync(new() { LastPassStarted = lastPass, LastPassCompleted = lastPass }, CancellationToken.None);

        await StartAsync();

        (await WaitForIdleAsync()).ShouldBe(T0 + Week);
        _server.Requests.ShouldBeEmpty();
    }

    private async Task StartAsync()
    {
        var client = new HttpClient(_server, disposeHandler: false);
        RangeHttpClient.Configure(client, "Singulink.Cryptography.Pwned.Service.Tests");

        var syncOptions = new RangeSyncOptions {
            DownloadConcurrency = 2,
            MaxAttempts = 1,
            RetryDelay = TimeSpan.Zero,
            MaxConsecutiveFailures = 3,
            ProgressInterval = TimeSpan.FromDays(30),
            TimeProvider = _time,
        };

        var options = Options.Create(new PwnedOptions { DataDirectory = _folder.Path, SyncInterval = Week, RetryInterval = RetryInterval });
        var synchronizer = new RangeSynchronizer(_store, client, _logger, syncOptions);

        _service = new RangeSyncService(_store, synchronizer, options, _time, _loggerFactory.CreateLogger<RangeSyncService>()) {
            WaitStarted = () => _waits.Release(),
        };

        await _service.StartAsync(CancellationToken.None);
    }

    /// <summary>
    /// Waits until the service is waiting for its next pass, and returns when that pass is due.
    /// </summary>
    private async Task<DateTimeOffset?> WaitForIdleAsync()
    {
        (await _waits.WaitAsync(TimeSpan.FromSeconds(20))).ShouldBeTrue("The service didn't start waiting.");
        return _service!.NextPass;
    }
}
