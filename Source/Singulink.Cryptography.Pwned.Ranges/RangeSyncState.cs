using System.Text.Json.Serialization;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Sync progress saved in the data folder, shared by every process that syncs the folder.
/// </summary>
public sealed record RangeSyncState
{
    /// <summary>
    /// Gets the time the last completed full pass started. Every range was checked at or after this time.
    /// </summary>
    public DateTimeOffset? LastPassStarted { get; init; }

    /// <summary>
    /// Gets the time the last full pass completed.
    /// </summary>
    public DateTimeOffset? LastPassCompleted { get; init; }

    /// <summary>
    /// Gets the time the current full pass started, or <see langword="null"/> if no full pass is in progress or interrupted.
    /// </summary>
    public DateTimeOffset? CurrentPassStarted { get; init; }

    /// <summary>
    /// Gets the prefix the current full pass resumes from. Every range before it has been checked.
    /// </summary>
    public int CurrentPassPosition { get; init; }

    /// <summary>
    /// Gets the ranges that failed in the last full pass and haven't been checked successfully since. Retry passes check them again.
    /// </summary>
    public IReadOnlyList<int>? FailedPrefixes { get; init; }
}

[JsonSerializable(typeof(RangeSyncState))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class RangeSyncStateJsonContext : JsonSerializerContext;
