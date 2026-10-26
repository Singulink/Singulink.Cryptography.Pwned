namespace Singulink.Cryptography.Pwned;

/// <summary>
/// Represents the result of a password check when a password was found in the database.
/// </summary>
/// <param name="Count">The number of times the password appeared in breaches.</param>
public record CheckPasswordResult(int Count);
