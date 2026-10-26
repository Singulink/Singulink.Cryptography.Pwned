using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Looks up password hashes in a <see cref="RangeStore"/>. A range that a lookup needs but that isn't stored, is invalid or can't be read is downloaded
/// from Have I Been Pwned first.
/// </summary>
/// <remarks>
/// A downloaded range answers the lookups waiting for it and is then stored in the data folder. Lookups in the same range share one download, and
/// downloads are written without the sync lock, so every instance using a data folder can download ranges on demand.
/// </remarks>
[SuppressMessage(
    "Design",
    "CA1001:Types that own disposable fields should be disposable",
    Justification = "The semaphore's wait handle is never used, so there is nothing to dispose.")]
public sealed class RangeFetcher
{
    private readonly RangeStore _store;
    private readonly RangeDownloader _downloader;
    private readonly RangeFetchOptions _options;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _downloadGate;
    private readonly LogThrottle _downloadFailureLog;
    private readonly LogThrottle _writeFailureLog;

    // The downloads in progress by prefix. An entry is removed once its range is written (or the download or write failed), so a range is downloaded
    // at most once until it is stored.
    private readonly Dictionary<int, Fetch> _fetches = [];
    private readonly Lock _fetchesLock = new();

    private long _downloads;
    private long _failures;

    /// <summary>
    /// Initializes a new instance of the <see cref="RangeFetcher"/> class.
    /// </summary>
    /// <param name="store">The store to look up hashes in and store downloaded ranges in.</param>
    /// <param name="httpClient">A client configured with <see cref="RangeHttpClient.Configure(HttpClient, string)"/>.</param>
    /// <param name="logger">The logger for failed downloads and writes.</param>
    /// <param name="options">The on-demand download options.</param>
    public RangeFetcher(RangeStore store, HttpClient httpClient, ILogger? logger = null, RangeFetchOptions? options = null)
    {
        _options = options ?? new();

        if (_options.MaxConcurrentDownloads < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "The maximum number of concurrent downloads must be at least 1.");

        if (_options.Timeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options), "The timeout must be positive.");

        _store = store;
        _downloader = new RangeDownloader(httpClient, _options.GetDownloadOptions());
        _logger = logger ?? NullLogger.Instance;
        _downloadGate = new SemaphoreSlim(_options.MaxConcurrentDownloads);
        _downloadFailureLog = new LogThrottle(_options.TimeProvider, _options.FailureLogInterval);
        _writeFailureLog = new LogThrottle(_options.TimeProvider, _options.FailureLogInterval);
    }

    /// <summary>
    /// Gets the number of ranges downloaded on demand, whether or not they could be stored.
    /// </summary>
    public long Downloads => Interlocked.Read(ref _downloads);

    /// <summary>
    /// Gets the number of on-demand downloads that failed or timed out. The lookups waiting for them returned <see
    /// cref="RangeLookupStatus.Unavailable"/>.
    /// </summary>
    public long Failures => Interlocked.Read(ref _failures);

    /// <summary>
    /// Gets the number of downloads in progress, including downloaded ranges that are still being written.
    /// </summary>
    internal int ActiveFetches
    {
        get {
            lock (_fetchesLock)
                return _fetches.Count;
        }
    }

    /// <summary>
    /// Looks up a SHA-1 password hash. If its range isn't stored, is invalid or can't be read, the range is downloaded, the lookup is answered from the
    /// download and the range is stored. Returns <see cref="RangeLookupStatus.Unavailable"/> if the download fails or times out.
    /// </summary>
    /// <param name="sha1Hash">The 20-byte SHA-1 hash.</param>
    /// <param name="cancellationToken">A token to stop waiting. A download continues for other lookups and is still stored.</param>
    public async ValueTask<RangeLookupResult> LookupAsync(ReadOnlyMemory<byte> sha1Hash, CancellationToken cancellationToken = default)
    {
        if (sha1Hash.Length is not 20)
            throw new ArgumentException("SHA-1 hashes are 20 bytes.", nameof(sha1Hash));

        int prefix = RangeFile.GetPrefix(sha1Hash.Span);

        if (prefix >= _store.TotalRanges)
            return new(RangeLookupStatus.Unavailable, 0);

        Fetch? fetch = null;

        for (int attempt = 1; fetch is null; attempt++)
        {
            int generation = _store.GetGeneration(prefix);
            RangeLookupResult result = await _store.LookupAsync(sha1Hash, cancellationToken);

            if (result.Status is not RangeLookupStatus.Unavailable)
                return result;

            Fetch? started = null;

            lock (_fetchesLock)
            {
                // A download writes the range before its entry is removed, so if there is no entry and the range was written since the lookup
                // started, it is looked up once more instead of being downloaded again.
                if (!_fetches.TryGetValue(prefix, out fetch) && (attempt > 1 || _store.GetGeneration(prefix) == generation))
                {
                    fetch = started = new Fetch();
                    _fetches.Add(prefix, started);
                }
            }

            if (started is not null)
                _ = Task.Run(() => RunAsync(prefix, started), CancellationToken.None);
        }

        byte[]? records = await fetch.Records.Task.WaitAsync(cancellationToken);

        if (records is null)
            return new(RangeLookupStatus.Unavailable, 0);

        byte[] suffix = new byte[RangeFile.SuffixSize];
        RangeFile.GetSuffix(sha1Hash.Span, suffix);

        return RangeFile.Find(records, suffix);
    }

    /// <summary>
    /// Downloads a range, answers the lookups waiting for it, then writes it. Never throws.
    /// </summary>
    private async Task RunAsync(int prefix, Fetch fetch)
    {
        DownloadResult? result = null;
        bool answered = false;

        try
        {
            result = await DownloadAsync(prefix);

            if (result.Outcome is DownloadOutcome.Downloaded)
            {
                byte[] downloaded = result.Buffer!;
                Interlocked.Increment(ref _downloads);
                answered = fetch.Records.TrySetResult(downloaded.AsSpan(RangeFile.HeaderSize, result.RecordCount * RangeFile.RecordSize).ToArray());

                // Not canceled: the range is downloaded already, and writing it takes moments.
                await _store.WriteRangeAsync(prefix, downloaded, result.RecordCount, result.ETag, CancellationToken.None);
                Log.RangeDownloadedOnDemand(_logger, FormatPrefix(prefix));
            }
            else
            {
                Interlocked.Increment(ref _failures);
                LogDownloadFailure(prefix, result.FailureReason ?? "Unexpected response.", result.Exception);
            }
        }
        catch (Exception ex) when (answered)
        {
            // The lookups were answered from the download, so they don't depend on the write (e.g. the disk is full or the folder is read-only).
            LogWriteFailure(prefix, ex);
        }
        catch (Exception ex)
        {
            // Unexpected.
            Interlocked.Increment(ref _failures);
            LogDownloadFailure(prefix, ex.Message, ex);
        }
        finally
        {
            if (result?.Buffer is { } buffer)
                ArrayPool<byte>.Shared.Return(buffer);

            lock (_fetchesLock)
                _fetches.Remove(prefix);

            // If the download failed, the lookups waiting for it are answered as unavailable. Lookups that start from now on download it again.
            fetch.Records.TrySetResult(null);
        }
    }

    private async Task<DownloadResult> DownloadAsync(int prefix)
    {
        // The download has its own timeout, so lookups that stop waiting for it don't cancel it for the others.
        using var timeout = new CancellationTokenSource(_options.Timeout, _options.TimeProvider);
        bool entered = false;

        try
        {
            await _downloadGate.WaitAsync(timeout.Token);
            entered = true;

            // There is no valid stored range to compare the download with, so the check for responses that shrank doesn't apply (as for ranges a sync
            // pass finds missing or invalid). Responses with a Content-MD5 header are still checked against it.
            return await _downloader.DownloadAsync(prefix, etag: null, minRecordCount: 0, timeout.Token);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            string reason = string.Create(CultureInfo.InvariantCulture, $"The download timed out after {_options.Timeout.TotalSeconds:0.#} seconds.");
            return DownloadResult.Failed(reason, null);
        }
        finally
        {
            if (entered)
                _downloadGate.Release();
        }
    }

    private void LogDownloadFailure(int prefix, string reason, Exception? exception)
    {
        if (!_downloadFailureLog.TryLog(out int notLogged))
            return;

        if (notLogged > 0)
            Log.OnDemandDownloadFailuresNotLogged(_logger, notLogged);

        Log.OnDemandDownloadFailed(_logger, FormatPrefix(prefix), reason, exception);
    }

    private void LogWriteFailure(int prefix, Exception exception)
    {
        if (!_writeFailureLog.TryLog(out int notLogged))
            return;

        if (notLogged > 0)
            Log.OnDemandWriteFailuresNotLogged(_logger, notLogged);

        Log.OnDemandWriteFailed(_logger, FormatPrefix(prefix), exception);
    }

    private static string FormatPrefix(int prefix) => prefix.ToString("X5", CultureInfo.InvariantCulture);

    private sealed class Fetch
    {
        /// <summary>
        /// Gets the task that completes with the downloaded records, or <see langword="null"/> if the download failed.
        /// </summary>
        public TaskCompletionSource<byte[]?> Records { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    /// <summary>
    /// Lets a message through at most once per interval and counts the others.
    /// </summary>
    private sealed class LogThrottle
    {
        private readonly TimeProvider _time;
        private readonly TimeSpan _interval;
        private readonly Lock _lock = new();
        private long _lastLogged;
        private bool _hasLogged;
        private int _notLogged;

        public LogThrottle(TimeProvider time, TimeSpan interval)
        {
            _time = time;
            _interval = interval;
        }

        /// <summary>
        /// Returns whether to log a message now, and if so, how many messages weren't logged since the last one.
        /// </summary>
        public bool TryLog(out int notLogged)
        {
            lock (_lock)
            {
                long now = _time.GetTimestamp();

                if (_hasLogged && _time.GetElapsedTime(_lastLogged, now) < _interval)
                {
                    _notLogged++;
                    notLogged = 0;
                    return false;
                }

                _hasLogged = true;
                _lastLogged = now;
                notLogged = _notLogged;
                _notLogged = 0;
                return true;
            }
        }
    }
}
