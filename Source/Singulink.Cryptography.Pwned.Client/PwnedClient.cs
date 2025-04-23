using System.Net;
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
    public async Task<CheckPasswordResult?> CheckPasswordAsync(string password)
    {
        using HttpClient client = _httpClientFactory.CreateClient();
        Uri url = GetApiUrl("/CheckPassword", (nameof(password), password));

        return await client.GetOkOrNotFound<CheckPasswordResult>(url);
    }

    /// <summary>
    /// Checks the specified SHA1 password hash against the Pwned Passwords database.
    /// </summary>
    public async Task<CheckPasswordResult?> CheckPasswordHashAsync(string passwordHash)
    {
        using HttpClient client = _httpClientFactory.CreateClient();
        Uri url = GetApiUrl("/CheckPasswordHash", (nameof(passwordHash), passwordHash));

        return await client.GetOkOrNotFound<CheckPasswordResult>(url);
    }

    private Uri GetApiUrl(string path, params (string Name, object Value)[] queryStringParams)
    {
        if (ApiBaseUri == null)
            throw new InvalidOperationException("Must set API base URI.");

        var uri = new Uri(ApiBaseUri, path);

        if (queryStringParams.Length == 0)
            return uri;

        StringBuilder qs = new();

        bool first = true;

        foreach ((string Name, object Value) pair in queryStringParams.Where(p => p.Value != null))
        {
            if (!first)
                qs.Append('&');

            qs.Append(pair.Name);
            qs.Append('=');

            if (pair.Value is DateTime dateTime)
                qs.Append(new DateTime(dateTime.Ticks, DateTimeKind.Unspecified).ToString("O"));
            else
                qs.Append(WebUtility.UrlEncode(pair.Value.ToString()));

            first = false;
        }

        return new UriBuilder(uri) { Query = qs.ToString() }.Uri;
    }
}
