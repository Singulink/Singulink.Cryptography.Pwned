namespace Singulink.Cryptography.Pwned.Client;

/// <summary>
/// Interface for the Singulink Pwned Passwords API client.
/// </summary>
public interface IPwnedClient
{
    /// <summary>
    /// Checks the specified password against the Pwned Passwords database.
    /// </summary>
    public Task<CheckPasswordResult?> CheckPasswordAsync(string password);

    /// <summary>
    /// Checks the specified SHA1 password hash against the Pwned Passwords database.
    /// </summary>
    public Task<CheckPasswordResult?> CheckPasswordHashAsync(string passwordHash);
}