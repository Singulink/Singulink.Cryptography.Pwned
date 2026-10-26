using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Renames a file over another with POSIX semantics, so the rename succeeds while other processes have the target open (if they share delete access).
/// Needs Windows 10 1809 / Server 2019 or later and a file system that supports it (e.g. NTFS).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WindowsRename
{
    private const uint Delete = 0x00010000;
    private const uint Synchronize = 0x00100000;
    private const uint ShareAll = 7;
    private const uint OpenExisting = 3;
    private const int FileRenameInfoEx = 22;
    private const uint ReplaceIfExists = 0x1;
    private const uint PosixSemantics = 0x2;

    private const int ErrorInvalidFunction = 1;
    private const int ErrorAccessDenied = 5;
    private const int ErrorNotSupported = 50;
    private const int ErrorInvalidParameter = 87;

    /// <summary>
    /// Renames <paramref name="source"/> over <paramref name="destination"/>. Returns <see langword="false"/> if POSIX renames aren't supported, in which
    /// case nothing was done. Throws <see cref="IOException"/> or <see cref="UnauthorizedAccessException"/> if the rename failed.
    /// </summary>
    public static bool TryReplace(string source, string destination)
    {
        using SafeFileHandle handle = CreateFileW(source, Delete | Synchronize, ShareAll, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);

        if (handle.IsInvalid)
            throw CreateException(Marshal.GetLastPInvokeError(), source);

        // FILE_RENAME_INFO: flags (padded to pointer size), root directory handle, file name length in bytes, file name.
        byte[] name = Encoding.Unicode.GetBytes(destination);
        int lengthOffset = IntPtr.Size * 2;
        int nameOffset = lengthOffset + sizeof(uint);
        byte[] info = new byte[nameOffset + name.Length + sizeof(char)];

        BinaryPrimitives.WriteUInt32LittleEndian(info, ReplaceIfExists | PosixSemantics);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(lengthOffset), (uint)name.Length);
        name.CopyTo(info, nameOffset);

        if (SetFileInformationByHandle(handle, FileRenameInfoEx, info, (uint)info.Length))
            return true;

        int error = Marshal.GetLastPInvokeError();

        if (error is ErrorInvalidParameter or ErrorNotSupported or ErrorInvalidFunction)
            return false;

        throw CreateException(error, destination);
    }

    private static Exception CreateException(int error, string path)
    {
        string message = $"{new Win32Exception(error).Message} : '{path}'";
        return error is ErrorAccessDenied ? new UnauthorizedAccessException(message) : new IOException(message, unchecked((int)0x80070000) | error);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int fileInformationClass, byte[] fileInformation, uint bufferSize);
}
