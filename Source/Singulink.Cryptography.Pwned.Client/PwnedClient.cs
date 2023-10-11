using System.Text;
using System.Web;

namespace Singulink.Cryptography.Pwned.Client;

public class PwnedClient : IPwnedClient
{
    private readonly IHttpClientFactory _httpClientFactory;

    public static Uri ApiBaseUri { get; set; } = new Uri("https://pwned.singulink.com");

    public PwnedClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<CheckPasswordResult?> CheckPasswordAsync(string password)
    {
        HttpClient client = _httpClientFactory.CreateClient();
        Uri url = GetApiUrl("/CheckPassword", (nameof(password), password));

        return await client.GetOkOrNotFound<CheckPasswordResult>(url);
    }

    public async Task<CheckPasswordResult?> CheckPasswordHashAsync(string passwordHash)
    {
        HttpClient client = _httpClientFactory.CreateClient();
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
                qs.Append(HttpUtility.UrlEncode(pair.Value.ToString()));

            first = false;
        }

        return new UriBuilder(uri) { Query = qs.ToString() }.Uri;
    }
}
