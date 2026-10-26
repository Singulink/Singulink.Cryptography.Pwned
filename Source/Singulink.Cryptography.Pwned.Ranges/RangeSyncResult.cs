using System.Text.Json.Serialization;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Specifies which ranges a sync pass checks.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<RangeSyncPassKind>))]
public enum RangeSyncPassKind
{
    /// <summary>
    /// Checks every range, downloading the ones that are missing or have changed. An interrupted full pass resumes where it stopped.
    /// </summary>
    Full,

    /// <summary>
    /// Downloads ranges that are missing or invalid, and checks ranges that failed in the last full pass again.
    /// </summary>
    Retry,
}

/// <summary>
/// Specifies how a sync pass ended.
/// </summary>
public enum RangeSyncOutcome
{
    /// <summary>
    /// Every range in the pass was checked. Some may have failed.
    /// </summary>
    Completed,

    /// <summary>
    /// The pass stopped after too many consecutive failures, e.g. because Have I Been Pwned is unreachable.
    /// </summary>
    Aborted,

    /// <summary>
    /// The pass was canceled.
    /// </summary>
    Canceled,

    /// <summary>
    /// The pass didn't run because another process (or another pass) is syncing the data folder.
    /// </summary>
    LockHeld,
}

/// <summary>
/// The result of a sync pass.
/// </summary>
public sealed record RangeSyncResult
{
    /// <summary>
    /// Gets the kind of pass.
    /// </summary>
    public required RangeSyncPassKind Kind { get; init; }

    /// <summary>
    /// Gets how the pass ended.
    /// </summary>
    public required RangeSyncOutcome Outcome { get; init; }

    /// <summary>
    /// Gets the number of ranges checked by this run of the pass.
    /// </summary>
    public int RangesChecked { get; init; }

    /// <summary>
    /// Gets the number of ranges downloaded and written.
    /// </summary>
    public int RangesUpdated { get; init; }

    /// <summary>
    /// Gets the number of ranges that failed.
    /// </summary>
    public int RangesFailed { get; init; }

    /// <summary>
    /// Gets the uncompressed size of the downloaded range data in bytes.
    /// </summary>
    public long BytesDownloaded { get; init; }

    /// <summary>
    /// Gets how long this run of the pass took.
    /// </summary>
    public TimeSpan Duration { get; init; }
}

/// <summary>
/// The progress of a running sync pass.
/// </summary>
public sealed record RangeSyncProgress
{
    /// <summary>
    /// Gets the kind of pass.
    /// </summary>
    public required RangeSyncPassKind Kind { get; init; }

    /// <summary>
    /// Gets the time the pass started. A resumed full pass keeps its original start time.
    /// </summary>
    public required DateTimeOffset Started { get; init; }

    /// <summary>
    /// Gets the number of ranges the pass checks.
    /// </summary>
    public int RangesTotal { get; init; }

    /// <summary>
    /// Gets the number of ranges checked so far, including ranges checked before a full pass was resumed.
    /// </summary>
    public int RangesChecked { get; init; }

    /// <summary>
    /// Gets the number of ranges downloaded and written so far.
    /// </summary>
    public int RangesUpdated { get; init; }

    /// <summary>
    /// Gets the number of ranges that failed so far.
    /// </summary>
    public int RangesFailed { get; init; }

    /// <summary>
    /// Gets the uncompressed size of the range data downloaded so far in bytes.
    /// </summary>
    public long BytesDownloaded { get; init; }
}
