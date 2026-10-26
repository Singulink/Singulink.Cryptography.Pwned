using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// A data folder of Pwned Passwords range files.
/// </summary>
public sealed class RangeStore
{
    /// <summary>
    /// The number of records read around the predicted position of a hash (about 4 KB).
    /// </summary>
    internal const int WindowRecords = 186;

    /// <summary>
    /// The maximum number of range files written (and flushed) at the same time in a process.
    /// </summary>
    internal const int MaxConcurrentWrites = 4;

    internal const string SyncStateFileName = "sync-state.json";

    private const int RenameAttempts = 10;
    private const int OpenAttempts = 3;
    private const int TempSuffixLength = 1 + 32 + 4; // ".{guid:N}.tmp"

    /// <summary>
    /// The age a temp file must reach before <see cref="DeleteTempFiles"/> deletes it. Writes take well under a second.
    /// </summary>
    internal static readonly TimeSpan TempFileMinAge = TimeSpan.FromMinutes(10);

    private static readonly TimeSpan _renameRetryDelay = TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan _openRetryDelay = TimeSpan.FromMilliseconds(10);

    private static readonly SearchValues<char> _lowerHex = SearchValues.Create("0123456789abcdef");
    private static readonly SearchValues<char> _upperHex = SearchValues.Create("0123456789ABCDEF");

    // Writes flush synchronously, so only a few at a time may block thread pool threads, however many downloads run in parallel.
    private static readonly SemaphoreSlim _writeGate = new(MaxConcurrentWrites);

    private readonly ILogger _logger;

    // Ranges believed to be stored and valid. Only the scan, the sync and writes (including ranges downloaded on demand) set them. A lookup that finds
    // a range invalid clears it unless the file was replaced since the lookup started (see _generations); an on-demand download or the next retry pass
    // then downloads it again.
    private readonly RangeSet _stored;

    // Ranges whose header a lookup has checked since this process last wrote them.
    private readonly RangeSet _verified;

    // Incremented every time this process writes a range.
    private readonly int[] _generations;

    private readonly Lock _scanLock = new();
    private Task? _scanTask;
    private volatile bool _scanCompleted;
    private int _activeWrites;
    private int _peakConcurrentWrites;

    /// <summary>
    /// Initializes a new instance of the <see cref="RangeStore"/> class.
    /// </summary>
    /// <param name="dataPath">The full path of the data folder. It doesn't need to exist yet.</param>
    /// <param name="logger">The logger for problems with the data folder.</param>
    public RangeStore(string dataPath, ILogger? logger = null) : this(dataPath, RangeFile.TotalPrefixes, logger)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RangeStore"/> class that only uses the first <paramref name="prefixCount"/> prefixes (for tests).
    /// </summary>
    internal RangeStore(string dataPath, int prefixCount, ILogger? logger = null)
    {
        if (!Path.IsPathFullyQualified(dataPath))
            throw new ArgumentException("The data path must be a full path.", nameof(dataPath));

        ArgumentOutOfRangeException.ThrowIfLessThan(prefixCount, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(prefixCount, RangeFile.TotalPrefixes);

        DataPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataPath));
        TotalRanges = prefixCount;
        _logger = logger ?? NullLogger.Instance;
        _stored = new RangeSet(prefixCount);
        _verified = new RangeSet(prefixCount);
        _generations = new int[prefixCount];
    }

    /// <summary>
    /// Gets the full path of the data folder.
    /// </summary>
    public string DataPath { get; }

    /// <summary>
    /// Gets the total number of ranges.
    /// </summary>
    public int TotalRanges { get; }

    /// <summary>
    /// Gets the number of ranges stored, or <see langword="null"/> until <see cref="ScanAsync(CancellationToken)"/> has completed.
    /// </summary>
    public int? StoredRanges => _scanCompleted ? _stored.Count : null;

    /// <summary>
    /// Gets the highest number of this store's range files that were being written at the same time.
    /// </summary>
    internal int PeakConcurrentWrites => Volatile.Read(ref _peakConcurrentWrites);

    /// <summary>
    /// Finds which ranges are stored. Only scans the folder once; later calls wait for the same scan.
    /// </summary>
    /// <param name="cancellationToken">A token to stop waiting. The scan itself continues for other callers.</param>
    public Task ScanAsync(CancellationToken cancellationToken = default)
    {
        Task scanTask;

        lock (_scanLock)
        {
            if (_scanTask is null || _scanTask.IsFaulted)
                _scanTask = Task.Run(Scan, CancellationToken.None);

            scanTask = _scanTask;
        }

        return scanTask.WaitAsync(cancellationToken);
    }

    /// <summary>
    /// Looks up a SHA-1 password hash in the stored ranges. Returns <see cref="RangeLookupStatus.Unavailable"/> if the hash's range isn't stored, is
    /// invalid or can't be read; <see cref="RangeFetcher"/> downloads it in that case.
    /// </summary>
    /// <param name="sha1Hash">The 20-byte SHA-1 hash.</param>
    /// <param name="cancellationToken">A token to cancel the lookup.</param>
    public async ValueTask<RangeLookupResult> LookupAsync(ReadOnlyMemory<byte> sha1Hash, CancellationToken cancellationToken = default)
    {
        if (sha1Hash.Length is not 20)
            throw new ArgumentException("SHA-1 hashes are 20 bytes.", nameof(sha1Hash));

        int prefix = RangeFile.GetPrefix(sha1Hash.Span);

        if (prefix >= TotalRanges)
            return new(RangeLookupStatus.Unavailable, 0);

        int generation = GetGeneration(prefix);
        using SafeFileHandle? handle = await OpenForLookupAsync(GetRangePath(prefix), cancellationToken);

        if (handle is null)
            return new(RangeLookupStatus.Unavailable, 0);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(WindowRecords * RangeFile.RecordSize);

        try
        {
            long length = RandomAccess.GetLength(handle);

            if (!RangeFile.TryGetRecordCount(length, out int recordCount))
            {
                MarkInvalid(prefix, generation, "its length is invalid");
                return new(RangeLookupStatus.Unavailable, 0);
            }

            // The header is checked the first time a range is looked up, so a file of the right length with the wrong contents isn't trusted.

            if (!_verified.Contains(prefix))
            {
                Memory<byte> header = buffer.AsMemory(0, RangeFile.HeaderSize);

                if (!await ReadExactlyAsync(handle, header, 0, cancellationToken) ||
                    !RangeFile.TryReadHeader(header.Span, length, out int headerCount, out _) || headerCount != recordCount)
                {
                    MarkInvalid(prefix, generation, "its header is invalid");
                    return new(RangeLookupStatus.Unavailable, 0);
                }

                _verified.Add(prefix);
            }

            byte[] suffix = new byte[RangeFile.SuffixSize];
            RangeFile.GetSuffix(sha1Hash.Span, suffix);

            RangeLookupResult? result = await SearchAsync(handle, recordCount, suffix, buffer, cancellationToken);

            if (result is null)
            {
                MarkInvalid(prefix, generation, "its records are not in order");
                return new(RangeLookupStatus.Unavailable, 0);
            }

            return result.Value;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(RangeLookupStatus.Unavailable, 0);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Reads the sync state saved in the data folder. Returns an empty state if there is none or it is invalid. Throws <see cref="IOException"/> or <see
    /// cref="UnauthorizedAccessException"/> if the file can't be read.
    /// </summary>
    public RangeSyncState ReadSyncState()
    {
        string path = Path.Combine(DataPath, SyncStateFileName);
        byte[] json;

        try
        {
            json = ReadAllBytesWithRetry(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new();
        }

        try
        {
            RangeSyncState state = JsonSerializer.Deserialize(json, RangeSyncStateJsonContext.Default.RangeSyncState) ?? new();

            if (state.CurrentPassPosition < 0 || state.CurrentPassPosition > TotalRanges)
                state = state with { CurrentPassPosition = 0 };

            if (state.FailedPrefixes is { Count: > 0 } failed && failed.Any(p => p < 0 || p >= TotalRanges))
                state = state with { FailedPrefixes = [.. failed.Where(p => p >= 0 && p < TotalRanges)] };

            return state;
        }
        catch (JsonException ex)
        {
            Log.SyncStateInvalid(_logger, path, ex);
            return new();
        }
    }

    internal string GetRangePath(int prefix) => Path.Combine(DataPath, RangeFile.GetRelativePath(prefix));

    internal bool IsStored(int prefix) => _stored.Contains(prefix);

    internal int GetGeneration(int prefix) => Volatile.Read(ref _generations[prefix]);

    /// <summary>
    /// Sets whether a range is stored. Only the sync calls this; lookups use <see cref="MarkInvalid(int, int, string)"/>.
    /// </summary>
    internal void SetStored(int prefix, bool stored)
    {
        if (stored)
            _stored.Add(prefix);
        else
            _stored.Remove(prefix);
    }

    /// <summary>
    /// Marks a range a lookup found invalid as not stored, so the next retry pass downloads it again if an on-demand download doesn't replace it first,
    /// unless this process replaced the file since the lookup started (<paramref name="generation"/>).
    /// </summary>
    internal void MarkInvalid(int prefix, int generation, string reason)
    {
        _verified.Remove(prefix);

        if (!_stored.Remove(prefix))
            return;

        // A write increments the generation before marking the range stored, so either this sees the new generation or the write re-marks the range.
        if (GetGeneration(prefix) != generation)
        {
            _stored.Add(prefix);
            return;
        }

        Log.RangeFileInvalid(_logger, prefix.ToString("X5", CultureInfo.InvariantCulture), GetRangePath(prefix), reason);
    }

    /// <summary>
    /// Reads the header of a range file and returns its status, along with its ETag and record count if it is valid. With <paramref
    /// name="checkRecords"/> set, every record is checked too. Throws <see cref="IOException"/> or <see cref="UnauthorizedAccessException"/> if the
    /// file exists but can't be read.
    /// </summary>
    internal RangeFileStatus ReadHeader(int prefix, out string? etag, out int recordCount, bool checkRecords = false)
    {
        etag = null;
        recordCount = 0;

        SafeFileHandle handle;

        try
        {
            handle = File.OpenHandle(GetRangePath(prefix), FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return RangeFileStatus.Missing;
        }

        using (handle)
        {
            long length = RandomAccess.GetLength(handle);
            Span<byte> header = stackalloc byte[RangeFile.HeaderSize];

            if (length < RangeFile.HeaderSize || RandomAccess.Read(handle, header, 0) < RangeFile.HeaderSize ||
                !RangeFile.TryReadHeader(header, length, out recordCount, out etag))
            {
                return RangeFileStatus.Invalid;
            }

            if (checkRecords)
            {
                byte[] records = new byte[length - RangeFile.HeaderSize];

                if (RandomAccess.Read(handle, records, RangeFile.HeaderSize) < records.Length || !RangeFile.AreRecordsValid(records, checkCounts: true))
                {
                    etag = null;
                    recordCount = 0;
                    return RangeFileStatus.Invalid;
                }
            }

            return RangeFileStatus.Valid;
        }
    }

    /// <summary>
    /// Writes a range file. <paramref name="buffer"/> holds the records after <see cref="RangeFile.HeaderSize"/> bytes of space for the header.
    /// </summary>
    internal async Task WriteRangeAsync(int prefix, byte[] buffer, int recordCount, string? etag, CancellationToken cancellationToken)
    {
        RangeFile.WriteHeader(buffer, recordCount, etag);
        int length = RangeFile.HeaderSize + (recordCount * RangeFile.RecordSize);

        string path = GetRangePath(prefix);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        await _writeGate.WaitAsync(cancellationToken);

        try
        {
            int active = Interlocked.Increment(ref _activeWrites);
            InterlockedMax(ref _peakConcurrentWrites, active);

            await WriteFileAsync(path, buffer.AsMemory(0, length), cancellationToken);
        }
        finally
        {
            Interlocked.Decrement(ref _activeWrites);
            _writeGate.Release();
        }

        Interlocked.Increment(ref _generations[prefix]);
        _verified.Remove(prefix);
        _stored.Add(prefix);
    }

    internal async Task WriteSyncStateAsync(RangeSyncState state, CancellationToken cancellationToken)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(state, RangeSyncStateJsonContext.Default.RangeSyncState);
        Directory.CreateDirectory(DataPath);
        await WriteFileAsync(Path.Combine(DataPath, SyncStateFileName), json, cancellationToken);
    }

    /// <summary>
    /// Deletes temp files left behind by interrupted writes of this library. Temp files written in the last <see cref="TempFileMinAge"/> are kept: any
    /// process using the data folder may be writing them right now, since ranges downloaded on demand are written without the sync lock.
    /// </summary>
    internal int DeleteTempFiles()
    {
        var tempFiles = new List<FileInfo>();
        var options = new EnumerationOptions { IgnoreInaccessible = true, MatchType = MatchType.Simple };
        var dataFolder = new DirectoryInfo(DataPath);

        if (dataFolder.Exists)
            tempFiles.AddRange(dataFolder.EnumerateFiles(SyncStateFileName + ".*.tmp", options).Where(f => IsTempFileName(f.Name, SyncStateFileName.Length)));

        var rangesFolder = new DirectoryInfo(Path.Combine(DataPath, "ranges"));

        if (rangesFolder.Exists)
        {
            foreach (DirectoryInfo folder in rangesFolder.EnumerateDirectories("???", options))
            {
                if (IsUpperHex(folder.Name))
                {
                    tempFiles.AddRange(folder.EnumerateFiles("??.bin.*.tmp", options)
                        .Where(f => IsUpperHex(f.Name.AsSpan(0, 2)) && IsTempFileName(f.Name, "XX.bin".Length)));
                }
            }
        }

        DateTime cutoff = DateTime.UtcNow - TempFileMinAge;
        int deleted = 0;

        // Temp file names are never reused, so the write time read by the enumeration is up to date.
        foreach (FileInfo file in tempFiles.Where(f => f.LastWriteTimeUtc < cutoff))
        {
            try
            {
                file.Delete();
                deleted++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Log.TempFileDeleteFailed(_logger, file.FullName, ex);
            }
        }

        return deleted;

        // "{target name}.{guid:N}.tmp"
        static bool IsTempFileName(string name, int targetLength) =>
            name.Length == targetLength + TempSuffixLength && name[targetLength] is '.' && name.EndsWith(".tmp", StringComparison.Ordinal) &&
            !name.AsSpan(targetLength + 1, 32).ContainsAnyExcept(_lowerHex);

        static bool IsUpperHex(ReadOnlySpan<char> s) => !s.IsEmpty && !s.ContainsAnyExcept(_upperHex);
    }

    private void Scan()
    {
        string rangesPath = Path.Combine(DataPath, "ranges");
        var options = new EnumerationOptions { IgnoreInaccessible = false, MatchType = MatchType.Simple };

        int folderCount = (TotalRanges + 255) >> 8;
        int invalid = 0;

        for (int folder = 0; folder < folderCount; folder++)
        {
            string folderPath = Path.Combine(rangesPath, folder.ToString("X3", CultureInfo.InvariantCulture));

            try
            {
                if (!Directory.Exists(folderPath))
                    continue;

                foreach (FileInfo file in new DirectoryInfo(folderPath).EnumerateFiles("*.bin", options))
                {
                    if (!TryParseFileName(file.Name, out int low))
                        continue;

                    int prefix = (folder << 8) | low;

                    if (prefix >= TotalRanges)
                        continue;

                    if (RangeFile.TryGetRecordCount(file.Length, out _))
                        _stored.Add(prefix);
                    else
                        invalid++;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Log.ScanFolderFailed(_logger, folderPath, ex);
            }
        }

        if (invalid > 0)
            Log.ScanFoundInvalidFiles(_logger, invalid, DataPath);

        _scanCompleted = true;

        static bool TryParseFileName(string name, out int low)
        {
            low = 0;

            if (name.Length is not 6 || !name.EndsWith(".bin", StringComparison.Ordinal))
                return false;

            return char.IsAsciiHexDigitUpper(name[0]) && char.IsAsciiHexDigitUpper(name[1]) &&
                int.TryParse(name.AsSpan(0, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out low);
        }
    }

    /// <summary>
    /// Searches a range file, or returns <see langword="null"/> if the records read aren't in order (the file is damaged).
    /// </summary>
    private static async Task<RangeLookupResult?> SearchAsync(
        SafeFileHandle handle, int recordCount, byte[] suffix, byte[] window, CancellationToken cancellationToken)
    {
        // SHA-1 is uniform, so the suffix predicts where its record is. The window around the prediction almost always contains it; if not, the search
        // moves to the adjacent window. Consecutive windows overlap by one record so the search can't change direction.

        int windowSize = Math.Min(WindowRecords, recordCount);
        int start = Math.Clamp(PredictIndex(suffix, recordCount) - (windowSize / 2), 0, recordCount - windowSize);

        while (true)
        {
            Memory<byte> records = window.AsMemory(0, windowSize * RangeFile.RecordSize);
            long offset = RangeFile.HeaderSize + ((long)start * RangeFile.RecordSize);

            if (!await ReadExactlyAsync(handle, records, offset, cancellationToken) || !RangeFile.AreRecordsValid(records.Span, checkCounts: false))
                return null;

            int index = RangeFile.BinarySearch(records.Span, windowSize, suffix);

            if (index >= 0)
            {
                int count = BinaryPrimitives.ReadInt32LittleEndian(records.Span.Slice((index * RangeFile.RecordSize) + RangeFile.SuffixSize, sizeof(int)));
                return new(RangeLookupStatus.Found, count);
            }

            int insertAt = ~index;

            if (insertAt is 0 && start > 0)
                start = Math.Max(0, start + 1 - windowSize);
            else if (insertAt == windowSize && start + windowSize < recordCount)
                start = Math.Min(start + windowSize - 1, recordCount - windowSize);
            else
                return new(RangeLookupStatus.NotFound, 0);
        }
    }

    private static int PredictIndex(ReadOnlySpan<byte> suffix, int recordCount)
    {
        // The top 4 bits of a suffix are zero, so this is a 28-bit fraction of the suffix range.
        uint position = BinaryPrimitives.ReadUInt32BigEndian(suffix);
        return (int)(((ulong)position * (uint)recordCount) >> 28);
    }

    private static async ValueTask<bool> ReadExactlyAsync(SafeFileHandle handle, Memory<byte> buffer, long offset, CancellationToken cancellationToken)
    {
        while (!buffer.IsEmpty)
        {
            int read = await RandomAccess.ReadAsync(handle, buffer, offset, cancellationToken);

            if (read is 0)
                return false;

            buffer = buffer[read..];
            offset += read;
        }

        return true;
    }

    /// <summary>
    /// Opens a range file for a lookup, or returns <see langword="null"/> if it doesn't exist or can't be opened.
    /// </summary>
    private static async ValueTask<SafeFileHandle?> OpenForLookupAsync(string path, CancellationToken cancellationToken)
    {
        // Lookups share delete access so the sync can rename a new file over one that is being read.

        for (int attempt = 1; ; attempt++)
        {
            try
            {
                const FileOptions Options = FileOptions.Asynchronous | FileOptions.RandomAccess;
                return File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, Options);
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
            {
                return null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // E.g. a sharing violation, or a file that is being deleted on Windows.
                if (attempt >= OpenAttempts)
                    return null;
            }

            await Task.Delay(_openRetryDelay, cancellationToken);
        }
    }

    private static byte[] ReadAllBytesWithRetry(string path)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1);
                byte[] bytes = new byte[stream.Length];
                stream.ReadExactly(bytes);
                return bytes;
            }
            catch (IOException ex) when ((ex is not FileNotFoundException and not DirectoryNotFoundException) && attempt < OpenAttempts)
            {
                Thread.Sleep(_openRetryDelay);
            }
        }
    }

    /// <summary>
    /// Writes a file to a uniquely named temp file next to it, flushes it to disk, then renames it over the target, so the target is always either the
    /// old file or the complete new one.
    /// </summary>
    private static async Task WriteFileAsync(string path, ReadOnlyMemory<byte> contents, CancellationToken cancellationToken)
    {
        string tempPath = $"{path}.{Guid.NewGuid():N}.tmp";

        try
        {
            var options = new FileStreamOptions {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = 0,
                PreallocationSize = contents.Length,
            };

            using (var stream = new FileStream(tempPath, options))
            {
                stream.Write(contents.Span);
                stream.Flush(flushToDisk: true);
            }

            // A rename can fail while another process has the target open without sharing delete access (on Windows without POSIX renames, any reader).
            // Readers take microseconds, so retry for a moment.

            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    MoveReplacing(tempPath, path);
                    break;
                }
                catch (Exception ex) when ((ex is IOException or UnauthorizedAccessException) && attempt < RenameAttempts)
                {
                    await Task.Delay(_renameRetryDelay, cancellationToken);
                }
            }
        }
        catch
        {
            try
            {
                File.Delete(tempPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Deleted by a later sync pass once it is old enough.
            }

            throw;
        }
    }

    private static void MoveReplacing(string source, string destination)
    {
        if (OperatingSystem.IsWindows() && WindowsRename.TryReplace(source, destination))
            return;

        File.Move(source, destination, overwrite: true);
    }

    private static void InterlockedMax(ref int location, int value)
    {
        int current = Volatile.Read(ref location);

        while (value > current)
        {
            int previous = Interlocked.CompareExchange(ref location, value, current);

            if (previous == current)
                return;

            current = previous;
        }
    }
}
