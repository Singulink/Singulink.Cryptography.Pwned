using System.Security.Cryptography;
using System.Text;
using Singulink.Net.Http.Api;
using Singulink.Net.Http.Api.Client;

namespace Singulink.Cryptography.Pwned.Client;

/// <summary>
/// Client for the Singulink Pwned Passwords API. Errors that the service returns are thrown as <see cref="ApiException"/> types, with the error code and
/// the <c>Retry-After</c> time that the service sent (see <see cref="PwnedErrorCodes"/>).
/// </summary>
public sealed class PwnedClient : ApiClientBase, IPwnedClient
{
    private readonly Uri _baseAddress;

    /// <summary>
    /// Initializes a new instance of the <see cref="PwnedClient"/> class for the service at the specified address.
    /// </summary>
    public PwnedClient(Uri baseAddress) : base(PwnedJsonSerializerContext.Default)
    {
        _baseAddress = baseAddress;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PwnedClient"/> class for the service at the specified address, which sends its requests through the
    /// specified handler instead of the handler that all clients share. The client doesn't dispose the handler.
    /// </summary>
    public PwnedClient(Uri baseAddress, HttpMessageHandler handler) : this(baseAddress)
    {
        HttpHandler = handler;
    }

    /// <summary>
    /// Gets how long a request can take before it is cancelled: 15 seconds. A request that times out throws a <see cref="TaskCanceledException"/> whose
    /// inner exception is a <see cref="TimeoutException"/>.
    /// </summary>
    protected override TimeSpan RequestTimeout => TimeSpan.FromSeconds(15);

    /// <inheritdoc/>
    public async Task<int> GetBreachCountAsync(string password, CancellationToken cancellationToken = default)
    {
        string passwordHash = GetSha1Hash(password);

        try
        {
            var result = await GetAsync<CheckPasswordResult>("CheckPasswordHash", [("passwordHash", passwordHash)], cancellationToken).ConfigureAwait(false);
            return result.Count;
        }
        catch (NotFoundApiException ex) when (ex.ErrorCode is PwnedErrorCodes.PasswordNotFound)
        {
            // Other 404 responses, such as from an address that isn't the service's, are thrown.
            return 0;
        }
    }

    /// <inheritdoc/>
    protected override Uri GetBaseAddress() => _baseAddress;

    private static string GetSha1Hash(string input)
    {
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);

#if NET
        return Convert.ToHexString(SHA1.HashData(inputBytes));
#else
        using var sha1 = SHA1.Create();
        return BitConverter.ToString(sha1.ComputeHash(inputBytes)).Replace("-", string.Empty);
#endif
    }
}
