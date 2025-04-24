namespace Singulink.Cryptography.Pwned;

/// <summary>
/// Represents the result of a password check when a password was found in the database.
/// </summary>
public record CheckPasswordResult(int Count);