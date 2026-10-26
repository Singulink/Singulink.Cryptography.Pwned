namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// The result of looking up a password hash.
/// </summary>
/// <param name="Status">Whether the hash was found.</param>
/// <param name="Count">The number of times the password appeared in breaches if it was found; otherwise zero.</param>
public readonly record struct RangeLookupResult(RangeLookupStatus Status, int Count);

/// <summary>
/// Specifies the outcome of a password hash lookup.
/// </summary>
public enum RangeLookupStatus
{
    /// <summary>
    /// The hash was found.
    /// </summary>
    Found,

    /// <summary>
    /// The hash's range doesn't contain the hash.
    /// </summary>
    NotFound,

    /// <summary>
    /// The hash's range isn't stored, is invalid or can't be read, and couldn't be downloaded (or downloading it wasn't tried), so the result is
    /// unknown for now.
    /// </summary>
    Unavailable,
}

/// <summary>
/// Specifies the state of a range file on disk.
/// </summary>
internal enum RangeFileStatus
{
    Missing,
    Invalid,
    Valid,
}
