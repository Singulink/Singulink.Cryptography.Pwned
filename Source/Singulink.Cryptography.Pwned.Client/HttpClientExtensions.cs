using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;

namespace Singulink.Cryptography.Pwned.Client;

public static class HttpClientExtensions
{
    public static async Task<T?> GetOkOrNotFound<T>(this HttpClient client, Uri url)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await client.SendAsync(request);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            return await response.Content.ReadFromJsonAsync<T>() ?? throw new FormatException("Empty response.");
        }

        string errorMessage = await response.Content.ReadAsStringAsync();

        if (response.StatusCode == HttpStatusCode.NotFound)
            return default;

        if (string.IsNullOrWhiteSpace(errorMessage))
            errorMessage = string.Format("Unknown service error ({0}) - please try again later.", (int)response.StatusCode);

        throw new HttpRequestException(errorMessage, null, response.StatusCode);
    }
}
