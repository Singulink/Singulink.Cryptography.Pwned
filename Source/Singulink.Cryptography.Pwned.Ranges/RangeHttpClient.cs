using System.Net;
using System.Net.Http.Headers;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Creates and configures HTTP clients for the Have I Been Pwned range API.
/// </summary>
public static class RangeHttpClient
{
    /// <summary>
    /// The name of the HTTP client to register with <c>IHttpClientFactory</c>.
    /// </summary>
    public const string Name = "PwnedRanges";

    /// <summary>
    /// Gets the base address of the range API.
    /// </summary>
    public static Uri BaseAddress { get; } = new("https://api.pwnedpasswords.com/");

    /// <summary>
    /// Gets the timeout for a single request.
    /// </summary>
    public static TimeSpan Timeout { get; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Configures a client's base address, timeout, HTTP version and user agent.
    /// </summary>
    /// <param name="client">The client to configure.</param>
    /// <param name="product">The product name sent in the user agent, e.g. the name of the app.</param>
    public static void Configure(HttpClient client, string product)
    {
        client.BaseAddress = BaseAddress;
        client.Timeout = Timeout;
        client.DefaultRequestVersion = HttpVersion.Version20;
        client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(product, null));
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("(+https://github.com/Singulink/Singulink.Cryptography.Pwned)"));
    }

    /// <summary>
    /// Creates the handler for range API clients, with automatic decompression.
    /// </summary>
    public static SocketsHttpHandler CreateHandler() => new() {
        AutomaticDecompression = DecompressionMethods.All,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        EnableMultipleHttp2Connections = true,
    };
}
