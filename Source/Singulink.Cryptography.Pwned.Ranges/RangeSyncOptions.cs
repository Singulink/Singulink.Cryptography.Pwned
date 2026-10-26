namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Options for syncing ranges.
/// </summary>
public sealed class RangeSyncOptions
{
    /// <summary>
    /// The default number of ranges downloaded in parallel.
    /// </summary>
    public const int DefaultDownloadConcurrency = 32;

    /// <summary>
    /// The maximum number of ranges downloaded in parallel.
    /// </summary>
    public const int MaxDownloadConcurrency = 256;

    /// <summary>
    /// Gets the number of ranges downloaded in parallel. Defaults to <see cref="DefaultDownloadConcurrency"/>.
    /// </summary>
    public int DownloadConcurrency { get; init; } = DefaultDownloadConcurrency;

    /// <summary>
    /// Gets the number of attempts to download a range before it fails.
    /// </summary>
    internal int MaxAttempts { get; init; } = 4;

    /// <summary>
    /// Gets the delay before the first retry of a range. It doubles with each further retry.
    /// </summary>
    internal TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Gets the longest Retry-After from the server that is honored.
    /// </summary>
    internal TimeSpan MaxRetryAfter { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets the number of consecutive range failures that abort a pass, or 0 for twice the download concurrency (at least 10).
    /// </summary>
    internal int MaxConsecutiveFailures { get; init; }

    /// <summary>
    /// Gets the maximum number of range failures logged individually per pass.
    /// </summary>
    internal int MaxLoggedFailures { get; init; } = 20;

    /// <summary>
    /// Gets how often a pass logs its progress and saves its position.
    /// </summary>
    internal TimeSpan ProgressInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets the timeout for downloading a single range.
    /// </summary>
    internal TimeSpan RequestTimeout { get; init; } = RangeHttpClient.Timeout;

    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    internal int GetMaxConsecutiveFailures() => MaxConsecutiveFailures > 0 ? MaxConsecutiveFailures : Math.Max(10, DownloadConcurrency * 2);
}
