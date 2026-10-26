using Singulink.Cryptography.Pwned.Ranges;

namespace Singulink.Cryptography.Pwned.Service;

/// <summary>
/// The status of the service's range data.
/// </summary>
public sealed record ServiceStatus
{
    /// <summary>
    /// Gets the number of ranges stored, or <see langword="null"/> until the startup scan of the data folder has finished. In an instance that shares
    /// its data folder, ranges that other instances stored since it started may be missing from the count.
    /// </summary>
    public int? RangesStored { get; init; }

    /// <summary>
    /// Gets the total number of ranges.
    /// </summary>
    public int TotalRanges { get; init; }

    /// <summary>
    /// Gets a value indicating whether this instance syncs the data folder.
    /// </summary>
    public bool SyncEnabled { get; init; }

    /// <summary>
    /// Gets a value indicating whether a sync pass is running in this instance.
    /// </summary>
    public bool SyncRunning { get; init; }

    /// <summary>
    /// Gets the progress of the running pass.
    /// </summary>
    public RangeSyncProgress? CurrentPass { get; init; }

    /// <summary>
    /// Gets the time the last full pass over all ranges completed, by any process syncing the data folder.
    /// </summary>
    public DateTimeOffset? LastCompletedPass { get; init; }

    /// <summary>
    /// Gets the time the next pass is due in this instance.
    /// </summary>
    public DateTimeOffset? NextPass { get; init; }

    /// <summary>
    /// Gets a value indicating whether lookups in this instance download ranges that aren't stored, are invalid or can't be read.
    /// </summary>
    public bool OnDemandDownloadEnabled { get; init; }

    /// <summary>
    /// Gets the number of ranges this instance downloaded on demand since it started.
    /// </summary>
    public long OnDemandDownloads { get; init; }

    /// <summary>
    /// Gets the number of on-demand downloads that failed or timed out in this instance since it started. The lookups waiting for them got a 503.
    /// </summary>
    public long OnDemandFailures { get; init; }
}
