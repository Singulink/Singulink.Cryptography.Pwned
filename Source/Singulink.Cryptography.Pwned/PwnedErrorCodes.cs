namespace Singulink.Cryptography.Pwned;

/// <summary>
/// Provides the error codes of the service's own errors, which tell apart errors with the same status code.
/// </summary>
public static class PwnedErrorCodes
{
    /// <summary>
    /// The error code of a <c>404</c> response to a check whose password isn't in the Pwned Passwords data.
    /// </summary>
    public const string PasswordNotFound = "password-not-found";

    /// <summary>
    /// The error code of a <c>503</c> response to a check whose password hash's range isn't stored and couldn't be downloaded from Have I Been Pwned.
    /// </summary>
    public const string HibpUnavailable = "hibp-unavailable";

    /// <summary>
    /// The error code of a <c>503</c> response to a check whose password hash's range isn't stored, on a service that doesn't download ranges for checks.
    /// </summary>
    public const string RangeNotDownloaded = "range-not-downloaded";
}
