using Microsoft.Extensions.Options;
using Singulink.Cryptography.Pwned.Ranges;

namespace Singulink.Cryptography.Pwned.Service;

/// <summary>
/// Scans the data folder at startup, then keeps it in sync with Have I Been Pwned: a full pass every <see cref="PwnedOptions.SyncInterval"/>, and
/// retry passes for missing, invalid and failed ranges until there are none.
/// </summary>
internal sealed partial class RangeSyncService : BackgroundService
{
    private static readonly TimeSpan _lockRetryInterval = TimeSpan.FromMinutes(1);

    private readonly RangeStore _store;
    private readonly RangeSynchronizer _synchronizer;
    private readonly PwnedOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    // UTC ticks of the next pass, or 0. Stored as a long so other threads never read a torn value.
    private long _nextPassTicks;

    public RangeSyncService(
        RangeStore store, RangeSynchronizer synchronizer, IOptions<PwnedOptions> options, TimeProvider time, ILogger<RangeSyncService> logger)
    {
        _store = store;
        _synchronizer = synchronizer;
        _options = options.Value;
        _time = time;
        _logger = logger;
    }

    /// <summary>
    /// Gets the time the next pass is due, or <see langword="null"/> while a pass is running or if this instance doesn't sync.
    /// </summary>
    public DateTimeOffset? NextPass
    {
        get {
            long ticks = Volatile.Read(ref _nextPassTicks);
            return ticks is 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
        }
        private set => Volatile.Write(ref _nextPassTicks, value?.UtcTicks ?? 0);
    }

    /// <summary>
    /// Gets or sets an action called whenever the service starts waiting (its timer is registered by then). Tests use it to advance a fake clock.
    /// </summary>
    internal Action? WaitStarted { get; set; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // The scan runs in the background so startup isn't slowed down. Lookups don't need it.

        try
        {
            await _store.ScanAsync(stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        LogScanCompleted(_store.StoredRanges ?? 0, _store.TotalRanges, _store.DataPath);

        if (!_options.SyncEnabled)
        {
            LogSyncDisabled();
            return;
        }

        DateTimeOffset notBefore = DateTimeOffset.MinValue;
        bool lockHeldLogged = false;

        while (!stoppingToken.IsCancellationRequested)
        {
            // Nothing may escape this loop: a faulted hosted service stops the host. Errors are logged and retried after the retry interval.

            try
            {
                (RangeSyncPassKind kind, DateTimeOffset due) = GetNextPass(_store.ReadSyncState(), notBefore);
                TimeSpan wait = due - _time.GetUtcNow();

                if (wait > TimeSpan.Zero)
                {
                    // Look again at least every retry interval, e.g. to download ranges that lookups found invalid in the meantime.
                    NextPass = due;
                    await WaitAsync(wait < _options.RetryInterval ? wait : _options.RetryInterval, stoppingToken);
                    continue;
                }

                NextPass = null;
                RangeSyncResult result = await _synchronizer.RunPassAsync(kind, stoppingToken);
                DateTimeOffset now = _time.GetUtcNow();

                if (result.Outcome is RangeSyncOutcome.LockHeld)
                {
                    if (!lockHeldLogged)
                    {
                        LogLockHeld(_store.DataPath);
                        lockHeldLogged = true;
                    }

                    notBefore = now + _lockRetryInterval;
                    continue;
                }

                lockHeldLogged = false;

                // Missing and failed ranges are retried after the retry interval, so a failing range doesn't make passes run back to back.
                notBefore = result.Outcome is RangeSyncOutcome.Aborted || result.RangesFailed > 0 || _store.StoredRanges < _store.TotalRanges
                    ? now + _options.RetryInterval
                    : DateTimeOffset.MinValue;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                LogSyncFailed(ex);

                notBefore = _time.GetUtcNow() + _options.RetryInterval;
                NextPass = notBefore;

                try
                {
                    await WaitAsync(_options.RetryInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    private (RangeSyncPassKind Kind, DateTimeOffset Due) GetNextPass(RangeSyncState state, DateTimeOffset notBefore)
    {
        DateTimeOffset now = _time.GetUtcNow();
        DateTimeOffset fullDue = now;

        // Interrupted full passes resume right away. A last pass in the future (the clock was wrong) counts as now.
        if (state.CurrentPassStarted is null && state.LastPassStarted is { } lastStarted)
            fullDue = AddClamped(lastStarted < now ? lastStarted : now, _options.SyncInterval);

        // Missing, invalid and failed ranges are retried right away, unless the last pass just failed or left some (notBefore).
        bool retryNeeded = _store.StoredRanges < _store.TotalRanges || state.FailedPrefixes is { Count: > 0 };
        DateTimeOffset retryDue = retryNeeded ? now : DateTimeOffset.MaxValue;

        (RangeSyncPassKind kind, DateTimeOffset due) = fullDue <= retryDue ? (RangeSyncPassKind.Full, fullDue) : (RangeSyncPassKind.Retry, retryDue);
        return (kind, due < notBefore ? notBefore : due);
    }

    private Task WaitAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        Task task = Task.Delay(delay, _time, cancellationToken);
        WaitStarted?.Invoke();
        return task;
    }

    private static DateTimeOffset AddClamped(DateTimeOffset time, TimeSpan interval) =>
        time > DateTimeOffset.MaxValue - interval ? DateTimeOffset.MaxValue : time + interval;

    [LoggerMessage(1, LogLevel.Information, "Found {Stored} of {Total} ranges in '{DataPath}'.")]
    private partial void LogScanCompleted(int stored, int total, string dataPath);

    [LoggerMessage(2, LogLevel.Information, "Range sync is disabled on this instance.")]
    private partial void LogSyncDisabled();

    [LoggerMessage(3, LogLevel.Information, "Another process is syncing '{DataPath}'. This instance will try again later.")]
    private partial void LogLockHeld(string dataPath);

    [LoggerMessage(4, LogLevel.Error, "Range sync failed. It will be tried again after the retry interval.")]
    private partial void LogSyncFailed(Exception exception);
}
