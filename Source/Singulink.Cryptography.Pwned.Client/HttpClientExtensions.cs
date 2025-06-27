using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Serialization.Metadata;

namespace Singulink.Cryptography.Pwned.Client;

internal static class HttpClientExtensions
{
    public static async Task<T?> GetOkOrNotFound<T>(this HttpClient client, JsonTypeInfo<T> typeInfo, Uri url) where T : notnull
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await client.SendAsync(request);

        if (response.StatusCode is HttpStatusCode.NotFound)
            return default;

        if (response.StatusCode is HttpStatusCode.OK)
            return await response.Content.ReadFromJsonAsync<T>(typeInfo) ?? throw new FormatException("Unexpected empty response.");

        string errorMessage = await response.Content.ReadAsStringAsync();

        if (string.IsNullOrWhiteSpace(errorMessage))
            errorMessage = string.Format(CultureInfo.InvariantCulture, "Unknown service error ({0}) - please try again later.", (int)response.StatusCode);

#if NET
        throw new HttpRequestException(errorMessage, null, response.StatusCode);
#else
        throw new HttpRequestException(errorMessage, null);
#endif
    }
}
