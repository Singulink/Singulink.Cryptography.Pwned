using Microsoft.Win32.SafeHandles;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// The <c>sync.lock</c> file in the data folder, held open without sharing while a process syncs the folder. Works across processes and over SMB.
/// </summary>
internal sealed class SyncLock : IDisposable
{
    public const string FileName = "sync.lock";

    private readonly SafeFileHandle _handle;

    private SyncLock(SafeFileHandle handle)
    {
        _handle = handle;
    }

    /// <summary>
    /// Acquires the lock, or returns <see langword="null"/> if another process (or another pass in this process) holds it.
    /// </summary>
    public static SyncLock? TryAcquire(string dataPath)
    {
        Directory.CreateDirectory(dataPath);
        string path = Path.Combine(dataPath, FileName);

        try
        {
            return new SyncLock(File.OpenHandle(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None));
        }
        catch (IOException ex) when (IsSharingViolation(ex))
        {
            return null;
        }
    }

    public void Dispose() => _handle.Dispose();

    /// <summary>
    /// Gets a value indicating whether an exception from opening the lock file means another handle holds it, as opposed to another I/O error.
    /// </summary>
    internal static bool IsSharingViolation(IOException ex)
    {
        if (ex is FileNotFoundException or DirectoryNotFoundException or PathTooLongException)
            return false;

        // Windows: ERROR_SHARING_VIOLATION or ERROR_LOCK_VIOLATION. Elsewhere .NET locks the file with flock and reports a held lock with the
        // EWOULDBLOCK errno as the HResult (11 on Linux, 35 on macOS and the BSDs).
        if (OperatingSystem.IsWindows())
            return ex.HResult is unchecked((int)0x80070020) or unchecked((int)0x80070021);

        return ex.HResult == (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid() ? 11 : 35);
    }
}
