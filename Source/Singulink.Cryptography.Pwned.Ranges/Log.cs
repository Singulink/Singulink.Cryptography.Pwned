using Microsoft.Extensions.Logging;

namespace Singulink.Cryptography.Pwned.Ranges;

internal static partial class Log
{
    [LoggerMessage(1, LogLevel.Warning, "The sync state file '{Path}' is invalid and was ignored.")]
    public static partial void SyncStateInvalid(ILogger logger, string path, Exception exception);

    [LoggerMessage(2, LogLevel.Warning, "Could not delete temp file '{Path}'.")]
    public static partial void TempFileDeleteFailed(ILogger logger, string path, Exception exception);

    [LoggerMessage(3, LogLevel.Warning, "Could not scan range folder '{Path}'.")]
    public static partial void ScanFolderFailed(ILogger logger, string path, Exception exception);

    [LoggerMessage(10, LogLevel.Information, "Sync pass started ({Kind}) for {Count} ranges.")]
    public static partial void PassStarted(ILogger logger, RangeSyncPassKind kind, int count);

    [LoggerMessage(11, LogLevel.Information, "Sync pass resumed ({Kind}) at range {Prefix}; it started at {Started:u}.")]
    public static partial void PassResumed(ILogger logger, RangeSyncPassKind kind, string prefix, DateTimeOffset started);

    [LoggerMessage(12, LogLevel.Information,
        "Sync pass progress ({Kind}): {Checked}/{Total} ranges checked, {Updated} updated, {Failed} failed, " +
        "{RangesPerSecond:F0} ranges/s, {Megabytes:F1} MB received (uncompressed).")]
    public static partial void PassProgress(
        ILogger logger, RangeSyncPassKind kind, int @checked, int total, int updated, int failed, double rangesPerSecond, double megabytes);

    [LoggerMessage(13, LogLevel.Information,
        "Sync pass completed ({Kind}) in {Duration}: {Checked} ranges checked, {Updated} updated, {Failed} failed, {Megabytes:F1} MB received (uncompressed).")]
    public static partial void PassCompleted(
        ILogger logger, RangeSyncPassKind kind, string duration, int @checked, int updated, int failed, double megabytes);

    [LoggerMessage(14, LogLevel.Warning,
        "Sync pass aborted ({Kind}) after {ConsecutiveFailures} consecutive failures in {Duration}: " +
        "{Checked} ranges checked, {Updated} updated, {Failed} failed.")]
    public static partial void PassAborted(
        ILogger logger, RangeSyncPassKind kind, int consecutiveFailures, string duration, int @checked, int updated, int failed);

    [LoggerMessage(15, LogLevel.Information,
        "Sync pass canceled ({Kind}) after {Duration}: {Checked} ranges checked, {Updated} updated, {Failed} failed.")]
    public static partial void PassCanceled(ILogger logger, RangeSyncPassKind kind, string duration, int @checked, int updated, int failed);

    [LoggerMessage(16, LogLevel.Information, "Deleted {Count} temp files left by interrupted writes.")]
    public static partial void TempFilesDeleted(ILogger logger, int count);

    [LoggerMessage(17, LogLevel.Warning, "Range {Prefix} failed: {Reason}")]
    public static partial void RangeFailed(ILogger logger, string prefix, string reason);

    [LoggerMessage(18, LogLevel.Warning, "Range {Prefix} failed: {Reason}")]
    public static partial void RangeFailedWithException(ILogger logger, string prefix, string reason, Exception exception);

    [LoggerMessage(19, LogLevel.Warning, "More ranges failed in this pass; further failures are only counted.")]
    public static partial void RangeFailuresSuppressed(ILogger logger);

    [LoggerMessage(20, LogLevel.Warning, "Could not save the sync state.")]
    public static partial void SyncStateWriteFailed(ILogger logger, Exception exception);

    [LoggerMessage(21, LogLevel.Warning, "Range {Prefix} ('{Path}') is invalid because {Reason}. It will be downloaded again.")]
    public static partial void RangeFileInvalid(ILogger logger, string prefix, string path, string reason);

    [LoggerMessage(22, LogLevel.Warning, "Found {Count} range files with an invalid length in '{DataPath}'. They will be downloaded again.")]
    public static partial void ScanFoundInvalidFiles(ILogger logger, int count, string dataPath);

    [LoggerMessage(23, LogLevel.Warning, "Sync pass ({Kind}) had more than {Max} failed ranges, so it counts as aborted.")]
    public static partial void TooManyFailures(ILogger logger, RangeSyncPassKind kind, int max);

    [LoggerMessage(30, LogLevel.Debug, "Downloaded range {Prefix} on demand.")]
    public static partial void RangeDownloadedOnDemand(ILogger logger, string prefix);

    [LoggerMessage(31, LogLevel.Warning, "Range {Prefix} couldn't be downloaded on demand: {Reason}")]
    public static partial void OnDemandDownloadFailed(ILogger logger, string prefix, string reason, Exception? exception);

    [LoggerMessage(32, LogLevel.Warning, "{Count} more on-demand range downloads failed and weren't logged.")]
    public static partial void OnDemandDownloadFailuresNotLogged(ILogger logger, int count);

    [LoggerMessage(33, LogLevel.Warning, "Range {Prefix} was downloaded on demand but couldn't be stored. Lookups were answered from the download.")]
    public static partial void OnDemandWriteFailed(ILogger logger, string prefix, Exception exception);

    [LoggerMessage(34, LogLevel.Warning, "{Count} more ranges downloaded on demand couldn't be stored and weren't logged.")]
    public static partial void OnDemandWriteFailuresNotLogged(ILogger logger, int count);
}
