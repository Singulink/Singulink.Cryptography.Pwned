using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Singulink.Cryptography.Pwned.Client;

/// <summary>
/// Client for the Singulink Pwned Passwords API.
/// </summary>
public class PwnedClient : IPwnedClient
{
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// Gets or sets the base URI for the API.
    /// </summary>
    public static Uri ApiBaseUri { get; set; } = new Uri("https://pwned.singulink.com");

    /// <summary>
    /// Initializes a new instance of the <see cref="PwnedClient"/> class.
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
        using HttpClient client = _httpClientFactory.CreateClient();
        Uri url = GetApiUrl("/CheckPasswordHash", ("passwordHash", passwordHash));

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

    private static Uri GetApiUrl(string path, params (string Name, string? Value)[] queryStringParams)
    {
        if (ApiBaseUri == null)
            throw new InvalidOperationException("Must set API base URI.");

        var uri = new Uri(ApiBaseUri, path);

        if (queryStringParams.Length == 0)
            return uri;

        StringBuilder qs = new();

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
}
