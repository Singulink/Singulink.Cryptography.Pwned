using System.Buffers;
using System.Globalization;
using System.Runtime.ExceptionServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Syncs a <see cref="RangeStore"/> with Have I Been Pwned.
/// </summary>
public sealed class RangeSynchronizer
{
    /// <summary>
    /// The most failed ranges a full pass can record for retry passes. A full pass with more counts as aborted and resumes from its first failure.
    /// </summary>
    internal const int MaxRecordedFailures = 10_000;

    private readonly RangeStore _store;
    private readonly RangeDownloader _downloader;
    private readonly RangeSyncOptions _options;
    private readonly ILogger _logger;
    private volatile Pass? _currentPass;

    /// <summary>
    /// Initializes a new instance of the <see cref="RangeSynchronizer"/> class.
    /// </summary>
    /// <param name="store">The store to sync.</param>
    /// <param name="httpClient">A client configured with <see cref="RangeHttpClient.Configure(HttpClient, string)"/>.</param>
    /// <param name="logger">The logger for progress and failures.</param>
    /// <param name="options">The sync options.</param>
    public RangeSynchronizer(RangeStore store, HttpClient httpClient, ILogger? logger = null, RangeSyncOptions? options = null)
    {
        _options = options ?? new();

        if (_options.DownloadConcurrency is < 1 or > RangeSyncOptions.MaxDownloadConcurrency)
            throw new ArgumentOutOfRangeException(nameof(options), $"Download concurrency must be between 1 and {RangeSyncOptions.MaxDownloadConcurrency}.");

        _store = store;
        _downloader = new RangeDownloader(httpClient, _options);
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Gets the progress of the pass currently running, or <see langword="null"/> if none is.
    /// </summary>
    public RangeSyncProgress? CurrentPass => _currentPass?.GetProgress();

    /// <summary>
    /// Runs a sync pass. Only one pass at a time can sync a data folder, across all processes; if another one is running, this returns right away with
    /// <see cref="RangeSyncOutcome.LockHeld"/>.
    /// </summary>
    /// <param name="kind">Which ranges to check.</param>
    /// <param name="cancellationToken">A token to stop the pass. A canceled full pass resumes where it stopped the next time one runs.</param>
    public async Task<RangeSyncResult> RunPassAsync(RangeSyncPassKind kind, CancellationToken cancellationToken = default)
    {
        using SyncLock? syncLock = SyncLock.TryAcquire(_store.DataPath);

        if (syncLock is null)
            return new() { Kind = kind, Outcome = RangeSyncOutcome.LockHeld };

        await _store.ScanAsync(cancellationToken);

        int deleted = _store.DeleteTempFiles();

        if (deleted > 0)
            Log.TempFilesDeleted(_logger, deleted);

        TimeProvider time = _options.TimeProvider;
        RangeSyncState state = _store.ReadSyncState();
        Pass pass;

        if (kind is RangeSyncPassKind.Full)
        {
            if (state.CurrentPassStarted is { } started)
            {
                pass = new Pass(kind, started, state.CurrentPassPosition, _store.TotalRanges, null, null, time.GetTimestamp());
                Log.PassResumed(_logger, kind, FormatPrefix(state.CurrentPassPosition), started);
            }
            else
            {
                state = state with { CurrentPassStarted = time.GetUtcNow(), CurrentPassPosition = 0 };
                await _store.WriteSyncStateAsync(state, cancellationToken);

                pass = new Pass(kind, state.CurrentPassStarted.Value, 0, _store.TotalRanges, null, null, time.GetTimestamp());
                Log.PassStarted(_logger, kind, pass.Total);
            }
        }
        else
        {
            // Missing or invalid ranges, and ranges whose last check failed (they may have changed).
            var failed = (state.FailedPrefixes ?? []).ToHashSet();
            int[] prefixes = [.. Enumerable.Range(0, _store.TotalRanges).Where(p => !_store.IsStored(p) || failed.Contains(p))];

            pass = new Pass(kind, time.GetUtcNow(), 0, _store.TotalRanges, prefixes, failed, time.GetTimestamp());
            Log.PassStarted(_logger, kind, pass.Total);
        }

        _currentPass = pass;
        Exception? error = null;

        try
        {
            await RunWorkersAsync(pass, state, cancellationToken);
        }
        catch (Exception ex)
        {
            error = ex;
        }
        finally
        {
            _currentPass = null;
        }

        TimeSpan duration = time.GetElapsedTime(pass.RunStartTimestamp);

        RangeSyncOutcome outcome = cancellationToken.IsCancellationRequested ? RangeSyncOutcome.Canceled :
            pass.IsAborted || error is not null ? RangeSyncOutcome.Aborted : RangeSyncOutcome.Completed;

        RangeSyncState? newState = null;

        if (kind is RangeSyncPassKind.Full)
        {
            if (outcome is RangeSyncOutcome.Completed && pass.StaleFailureCount > MaxRecordedFailures)
            {
                Log.TooManyFailures(_logger, kind, MaxRecordedFailures);
                outcome = RangeSyncOutcome.Aborted;
            }

            newState = outcome is RangeSyncOutcome.Completed
                ? state with {
                    LastPassStarted = pass.Started,
                    LastPassCompleted = time.GetUtcNow(),
                    CurrentPassStarted = null,
                    CurrentPassPosition = 0,
                    FailedPrefixes = NullIfEmpty(pass.GetFailedPrefixes(null)),
                }
                : state with { CurrentPassPosition = pass.AdvanceWatermark() };
        }
        else
        {
            int[] failed = pass.GetFailedPrefixes(state.FailedPrefixes);

            if (!failed.SequenceEqual(state.FailedPrefixes ?? []))
                newState = state with { FailedPrefixes = NullIfEmpty(failed) };
        }

        // If the state can't be saved, the pass has to run again, so it doesn't count as completed.
        if (newState is not null && !await SaveStateAsync(newState) && outcome is RangeSyncOutcome.Completed)
            outcome = RangeSyncOutcome.Aborted;

        if (error is not null)
            ExceptionDispatchInfo.Throw(error);

        var result = new RangeSyncResult {
            Kind = kind,
            Outcome = outcome,
            RangesChecked = pass.Checked,
            RangesUpdated = pass.Updated,
            RangesFailed = pass.Failed,
            BytesDownloaded = pass.BytesDownloaded,
            Duration = duration,
        };

        LogResult(result, pass.ConsecutiveFailures);
        return result;

        static int[]? NullIfEmpty(int[] prefixes) => prefixes.Length is 0 ? null : prefixes;
    }

    private async Task RunWorkersAsync(Pass pass, RangeSyncState state, CancellationToken cancellationToken)
    {
        using var passCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var progressCts = new CancellationTokenSource();

        Task progressTask = ReportProgressAsync(pass, state, progressCts.Token);
        int workerCount = Math.Clamp(pass.Total - pass.StartPosition, 1, _options.DownloadConcurrency);

        try
        {
            await Task.WhenAll(Enumerable.Range(0, workerCount).Select(_ => Task.Run(() => RunWorkerAsync(pass, passCts), CancellationToken.None)));
        }
        finally
        {
            await progressCts.CancelAsync();
            await progressTask;
        }
    }

    private async Task RunWorkerAsync(Pass pass, CancellationTokenSource passCts)
    {
        CancellationToken token = passCts.Token;
        int maxConsecutiveFailures = _options.GetMaxConsecutiveFailures();

        while (!token.IsCancellationRequested && pass.TryTake(out int prefix))
        {
            bool succeeded;

            try
            {
                succeeded = await SyncRangeAsync(pass, prefix, token);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                return;
            }
            catch
            {
                // An unexpected error stops the whole pass.
                await passCts.CancelAsync();
                throw;
            }

            if (!succeeded && pass.ConsecutiveFailures >= maxConsecutiveFailures && pass.TryAbort())
                await passCts.CancelAsync();
        }
    }

    /// <summary>
    /// Checks one range and records the result in the pass. Returns whether it succeeded.
    /// </summary>
    private async Task<bool> SyncRangeAsync(Pass pass, int prefix, CancellationToken cancellationToken)
    {
        bool stored = _store.IsStored(prefix);
        var status = RangeFileStatus.Missing;
        string? etag = null;
        int recordCount = 0;

        // A full pass trusts the scan about missing ranges. A retry pass looks at the file in case another process stored it since, and checks every
        // record of a range that isn't marked as stored (e.g. a lookup found it invalid).

        if (stored || pass.Kind is RangeSyncPassKind.Retry)
        {
            try
            {
                status = _store.ReadHeader(prefix, out etag, out recordCount, checkRecords: !stored);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Probably temporary, so the range keeps its stored state and is checked again later.
                LogFailure(pass, prefix, "Could not read the range file.", ex);
                pass.RecordFailure(prefix, stale: stored);
                return false;
            }
        }

        bool valid = status is RangeFileStatus.Valid;

        if (valid)
        {
            if (!stored)
                _store.SetStored(prefix, true);

            if (pass.Kind is RangeSyncPassKind.Retry && !pass.IsFailedRetry(prefix))
            {
                pass.RecordSuccess(prefix, updated: false, 0);
                return true;
            }
        }

        // Ranges that are missing or invalid are downloaded unconditionally.
        DownloadResult result = await _downloader.DownloadAsync(prefix, valid ? etag : null, valid ? recordCount : 0, cancellationToken);

        if (result.Outcome is DownloadOutcome.NotModified)
        {
            pass.RecordSuccess(prefix, updated: false, 0);
            return true;
        }

        if (result.Outcome is DownloadOutcome.Failed)
        {
            if (!valid)
                _store.SetStored(prefix, false);

            LogFailure(pass, prefix, result.FailureReason!, result.Exception);
            pass.RecordFailure(prefix, stale: valid);
            return false;
        }

        try
        {
            await _store.WriteRangeAsync(prefix, result.Buffer!, result.RecordCount, result.ETag, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            if (!valid)
                _store.SetStored(prefix, false);

            LogFailure(pass, prefix, "Could not write the range file.", ex);
            pass.RecordFailure(prefix, stale: valid);
            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(result.Buffer!);
        }

        pass.RecordSuccess(prefix, updated: true, result.ResponseLength);
        return true;
    }

    private async Task ReportProgressAsync(Pass pass, RangeSyncState state, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_options.ProgressInterval, _options.TimeProvider);

        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                double seconds = _options.TimeProvider.GetElapsedTime(pass.RunStartTimestamp).TotalSeconds;
                RangeSyncProgress progress = pass.GetProgress();

                Log.PassProgress(
                    _logger,
                    pass.Kind,
                    progress.RangesChecked,
                    progress.RangesTotal,
                    progress.RangesUpdated,
                    progress.RangesFailed,
                    seconds > 0 ? pass.Checked / seconds : 0,
                    ToMegabytes(progress.BytesDownloaded));

                if (pass.Kind is RangeSyncPassKind.Full)
                    await SaveStateAsync(state with { CurrentPassPosition = pass.AdvanceWatermark() });
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task<bool> SaveStateAsync(RangeSyncState state)
    {
        try
        {
            await _store.WriteSyncStateAsync(state, CancellationToken.None);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.SyncStateWriteFailed(_logger, ex);
            return false;
        }
    }

    private void LogFailure(Pass pass, int prefix, string reason, Exception? exception)
    {
        int logged = pass.IncrementLoggedFailures();

        if (logged <= _options.MaxLoggedFailures)
        {
            if (exception is null)
                Log.RangeFailed(_logger, FormatPrefix(prefix), reason);
            else
                Log.RangeFailedWithException(_logger, FormatPrefix(prefix), reason, exception);
        }
        else if (logged == _options.MaxLoggedFailures + 1)
        {
            Log.RangeFailuresSuppressed(_logger);
        }
    }

    private void LogResult(RangeSyncResult result, int consecutiveFailures)
    {
        string duration = FormatDuration(result.Duration);

        switch (result.Outcome)
        {
            case RangeSyncOutcome.Completed:
                Log.PassCompleted(
                    _logger, result.Kind, duration, result.RangesChecked, result.RangesUpdated, result.RangesFailed, ToMegabytes(result.BytesDownloaded));
                break;
            case RangeSyncOutcome.Aborted:
                Log.PassAborted(_logger, result.Kind, consecutiveFailures, duration, result.RangesChecked, result.RangesUpdated, result.RangesFailed);
                break;
            case RangeSyncOutcome.Canceled:
                Log.PassCanceled(_logger, result.Kind, duration, result.RangesChecked, result.RangesUpdated, result.RangesFailed);
                break;
        }
    }

    private static string FormatPrefix(int prefix) => prefix.ToString("X5", CultureInfo.InvariantCulture);

    private static string FormatDuration(TimeSpan duration) =>
        duration.ToString(duration.TotalDays >= 1 ? @"d\.hh\:mm\:ss" : @"hh\:mm\:ss", CultureInfo.InvariantCulture);

    private static double ToMegabytes(long bytes) => bytes / (1024.0 * 1024.0);

    private sealed class Pass
    {
        private readonly int[]? _prefixes;
        private readonly HashSet<int>? _failedRetries;
        private readonly RangeSet _succeeded;
        private readonly RangeSet _staleFailures;
        private readonly Lock _watermarkLock = new();

        private int _next;
        private int _watermark;
        private int _checked;
        private int _updated;
        private int _failed;
        private int _consecutiveFailures;
        private int _loggedFailures;
        private long _bytesDownloaded;
        private int _aborted;

        // Checks the given prefixes, or every prefix from startPosition on if prefixes is null. failedRetries are the prefixes that failed in the last
        // full pass, which a retry pass checks for changes even if they are stored.
        public Pass(
            RangeSyncPassKind kind,
            DateTimeOffset started,
            int startPosition,
            int totalRanges,
            int[]? prefixes,
            HashSet<int>? failedRetries,
            long runStartTimestamp)
        {
            Kind = kind;
            Started = started;
            StartPosition = startPosition;
            RunStartTimestamp = runStartTimestamp;
            Total = prefixes?.Length ?? totalRanges;

            _prefixes = prefixes;
            _failedRetries = failedRetries;
            _succeeded = new RangeSet(totalRanges);
            _staleFailures = new RangeSet(totalRanges);
            _next = startPosition;
            _watermark = startPosition;
        }

        public RangeSyncPassKind Kind { get; }

        public DateTimeOffset Started { get; }

        public int StartPosition { get; }

        public int Total { get; }

        public long RunStartTimestamp { get; }

        public int Checked => Volatile.Read(ref _checked);

        public int Updated => Volatile.Read(ref _updated);

        public int Failed => Volatile.Read(ref _failed);

        public long BytesDownloaded => Interlocked.Read(ref _bytesDownloaded);

        public int ConsecutiveFailures => Volatile.Read(ref _consecutiveFailures);

        public int StaleFailureCount => _staleFailures.Count;

        public bool IsAborted => Volatile.Read(ref _aborted) is not 0;

        public bool TryTake(out int prefix)
        {
            int index = Interlocked.Increment(ref _next) - 1;

            if (index >= Total)
            {
                prefix = 0;
                return false;
            }

            prefix = _prefixes is null ? index : _prefixes[index];
            return true;
        }

        public bool IsFailedRetry(int prefix) => _failedRetries?.Contains(prefix) is true;

        // Counters are updated before the checked count, so progress read while a pass runs is consistent.

        public void RecordSuccess(int prefix, bool updated, int bytesDownloaded)
        {
            Interlocked.Add(ref _bytesDownloaded, bytesDownloaded);

            if (updated)
                Interlocked.Increment(ref _updated);

            _succeeded.Add(prefix);
            _staleFailures.Remove(prefix);
            Volatile.Write(ref _consecutiveFailures, 0);
            Interlocked.Increment(ref _checked);
        }

        // A stale failure is a range that is stored but couldn't be checked for changes, so a retry pass should check it again.
        public void RecordFailure(int prefix, bool stale)
        {
            Interlocked.Increment(ref _failed);

            if (stale)
                _staleFailures.Add(prefix);

            Interlocked.Increment(ref _consecutiveFailures);
            Interlocked.Increment(ref _checked);
        }

        public bool TryAbort() => Interlocked.Exchange(ref _aborted, 1) is 0;

        public int IncrementLoggedFailures() => Interlocked.Increment(ref _loggedFailures);

        /// <summary>
        /// Gets the failed ranges to save for retry passes: the previous ones (if any) that didn't succeed in this pass, plus this pass's stale failures.
        /// </summary>
        public int[] GetFailedPrefixes(IReadOnlyList<int>? previous)
        {
            IEnumerable<int> failed = Enumerable.Range(0, _staleFailures.Capacity).Where(_staleFailures.Contains);

            if (previous is not null)
                failed = failed.Concat(previous.Where(p => !_succeeded.Contains(p)));

            return [.. failed.Distinct().Order()];
        }

        /// <summary>
        /// Gets the position a full pass resumes from: every range before it succeeded. Failed ranges are checked again when the pass resumes.
        /// </summary>
        public int AdvanceWatermark()
        {
            lock (_watermarkLock)
            {
                while (_watermark < Total && _succeeded.Contains(_watermark))
                    _watermark++;

                return _watermark;
            }
        }

        public RangeSyncProgress GetProgress()
        {
            // Read the checked count first; the other counters are updated before it.
            int @checked = Checked;

            return new() {
                Kind = Kind,
                Started = Started,
                RangesTotal = Total,
                RangesChecked = Math.Min(StartPosition + @checked, Total),
                RangesUpdated = Updated,
                RangesFailed = Failed,
                BytesDownloaded = BytesDownloaded,
            };
        }
    }
}
