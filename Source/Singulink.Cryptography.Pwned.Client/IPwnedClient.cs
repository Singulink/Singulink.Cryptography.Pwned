namespace Singulink.Cryptography.Pwned.Client;

/// <summary>
/// Interface for the Singulink Pwned Passwords API client.
/// </summary>
public interface IPwnedClient
{
    /// <summary>
    /// Gets the number of times the specified password appears in the Pwned Passwords data. The password is hashed with SHA-1 over its UTF-8 bytes, and
    /// only the hash is sent to the service.
    /// </summary>
    /// <param name="password">The password to check.</param>
    /// <param name="cancellationToken">A token to cancel the request.</param>
    /// <returns>
    /// The number of times the password appears in the data, or 0 if it doesn't appear.
    /// </returns>
    /// <exception cref="Net.Http.Api.ApiException">The service returned an error, such as a <see cref="Net.Http.Api.ServiceUnavailableApiException"/> with
    /// one of the <see cref="PwnedErrorCodes"/> when the password hash's range isn't available.</exception>
    public Task<int> GetBreachCountAsync(string password, CancellationToken cancellationToken = default);
}
