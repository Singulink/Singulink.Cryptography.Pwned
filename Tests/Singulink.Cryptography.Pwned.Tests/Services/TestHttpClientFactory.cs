using System.Net.Http;

namespace Singulink.Cryptography.Pwned.Tests;

public class TestHttpClientFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new HttpClient();
}
