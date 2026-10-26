namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Options for downloading ranges on demand.
/// </summary>
public sealed class RangeFetchOptions
{
    /// <summary>
    /// The default maximum number of ranges downloaded on demand at the same time.
    /// </summary>
    public const int DefaultMaxConcurrentDownloads = 16;

    /// <summary>
    /// Gets the maximum number of ranges downloaded on demand at the same time. Defaults to <see cref="DefaultMaxConcurrentDownloads"/>.
    /// </summary>
    public int MaxConcurrentDownloads { get; init; } = DefaultMaxConcurrentDownloads;

    /// <summary>
    /// Gets how long an on-demand download may take, including waiting for a free download and retries. Defaults to 10 seconds.
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Gets the number of attempts to download a range before it fails.
    /// </summary>
    internal int MaxAttempts { get; init; } = 3;

    /// <summary>
    /// Gets the delay before the first retry of a range. It doubles with each further retry.
    /// </summary>
    internal TimeSpan RetryDelay { get; init; } = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Gets the longest Retry-After from the server that is honored. Longer ones are shortened to this, since lookups are waiting.
    /// </summary>
    internal TimeSpan MaxRetryAfter { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Gets the timeout for a single request.
    /// </summary>
    internal TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets how often failed downloads and failed writes are logged at most (each kind separately). The others are counted in the next message.
    /// </summary>
    internal TimeSpan FailureLogInterval { get; init; } = TimeSpan.FromMinutes(1);

    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    internal RangeSyncOptions GetDownloadOptions() => new() {
        MaxAttempts = MaxAttempts,
        RetryDelay = RetryDelay,
        MaxRetryAfter = MaxRetryAfter,
        RequestTimeout = RequestTimeout,
        TimeProvider = TimeProvider,
    };
}
