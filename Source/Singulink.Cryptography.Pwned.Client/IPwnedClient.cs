namespace Singulink.Cryptography.Pwned.Client;

/// <summary>
/// Interface for the Singulink Pwned Passwords API client.
/// </summary>
public interface IPwnedClient
{
    /// <summary>
    /// Checks the specified password against the Pwned Passwords database.
    /// </summary>
    /// <returns>
    /// A <see cref="CheckPasswordResult"/> if the password is found in the database; otherwise <see langword="null"/>.
    /// </returns>
    public Task<CheckPasswordResult?> CheckPasswordAsync(string password);

    /// <summary>
    /// Checks the specified SHA1 password hash against the Pwned Passwords database.
    /// </summary>
    /// <returns>
    /// A <see cref="CheckPasswordResult"/> if the password is found in the database; otherwise <see langword="null"/>.
    /// </returns>
    public Task<CheckPasswordResult?> CheckPasswordHashAsync(string passwordHash);
}