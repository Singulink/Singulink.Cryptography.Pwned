using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Singulink.Cryptography.Pwned.Client;

#pragma warning disable SA1513 // Closing brace should be followed by blank line\

/// <summary>
/// Client for the Singulink Pwned Passwords API.
/// </summary>
public class PwnedClient : IPwnedClient
{
    #region Static HttpClient

    private const int DefaultHttpClientRefreshDnsTimeout = 60 * 1000;

    private static readonly object _syncLock = new();

    private static HttpClient? _defaultHttpClient;

    private static HttpClient DefaultHttpClient
    {
        get {
            return _defaultHttpClient ?? GetOrCreateSlow();

            [MethodImpl(MethodImplOptions.NoInlining)]
            static HttpClient GetOrCreateSlow()
            {
                lock (_syncLock)
                {
                    if (_defaultHttpClient is not null)
                        return _defaultHttpClient;
#if NET
                    _defaultHttpClient = new HttpClient(new SocketsHttpHandler {
                        PooledConnectionLifetime = TimeSpan.FromMilliseconds(DefaultHttpClientRefreshDnsTimeout),
                    });
#else
                    _defaultHttpClient = new HttpClient();
                    SetDnsRefreshTimeout(DefaultBaseAddress, DefaultHttpClientRefreshDnsTimeout);
#endif

                    return _defaultHttpClient;
                }
            }
        }
    }

    #endregion

    private readonly IHttpClientFactory? _httpClientFactory;

    /// <summary>
    /// Gets or sets the default base address for the API. Defaults to the Singulink Pwned API service endpoint (https://pwned.singulink.com).
    /// </summary>
    public static Uri DefaultBaseAddress
    {
        get;
        set {
#if !NET
            SetDnsRefreshTimeout(value, DefaultHttpClientRefreshDnsTimeout);
#endif
            field = value;
        }
    } = new Uri("https://pwned.singulink.com");

    /// <summary>
    /// Initializes a new instance of the <see cref="PwnedClient"/> class.
    /// </summary>
    public PwnedClient() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="PwnedClient"/> class using the specified HTTP client factory. If the <see cref="HttpClient"/> instances
    /// provided by the factory have <see cref="HttpClient.BaseAddress"/> set, that is used instead of <see cref="DefaultBaseAddress"/>.
    /// </summary>
    public PwnedClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Checks the specified password against the Pwned Passwords database.
    /// </summary>
    public Task<CheckPasswordResult?> CheckPasswordAsync(string password)
    {
        string passwordHash = GetSHA1Hash(password);
        return CheckPasswordHashAsync(passwordHash);
    }

    /// <summary>
    /// Checks the specified SHA1 password hash against the Pwned Passwords database.
    /// </summary>
    public async Task<CheckPasswordResult?> CheckPasswordHashAsync(string passwordHash)
    {
        var client = _httpClientFactory?.CreateClient() ?? DefaultHttpClient;
        var url = GetApiUrl(client.BaseAddress ?? DefaultBaseAddress, "/CheckPasswordHash", ("passwordHash", passwordHash));

        return await client.GetOkOrNotFound(PwnedJsonSerializerContext.Default.CheckPasswordResult, url);
    }

    private static string GetSHA1Hash(string input)
    {
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);

#if NET
        byte[] hashBytes = SHA1.HashData(inputBytes);
        return Convert.ToHexString(hashBytes);
#else
        using var sha1 = SHA1.Create();
        byte[] hashBytes = sha1.ComputeHash(inputBytes);

        return BitConverter.ToString(hashBytes).Replace("-", string.Empty);
#endif
    }

    private static Uri GetApiUrl(Uri baseAddress, string path, params (string Name, string? Value)[] queryStringParams)
    {
        var uri = new Uri(baseAddress, path);

        if (queryStringParams.Length == 0)
            return uri;

        var qs = new StringBuilder();

        bool first = true;

        foreach ((string name, string? value) in queryStringParams)
        {
            if (value is null)
                continue;

            if (!first)
                qs.Append('&');

            qs.Append(name);
            qs.Append('=');
            qs.Append(WebUtility.UrlEncode(value));

            first = false;
        }

        return new UriBuilder(uri) { Query = qs.ToString() }.Uri;
    }

#if !NET
    private static void SetDnsRefreshTimeout(Uri uri, int leaseTimeout)
    {
        var servicePoint = ServicePointManager.FindServicePoint(uri);
        servicePoint.ConnectionLeaseTimeout = leaseTimeout;
    }
#endif
}
