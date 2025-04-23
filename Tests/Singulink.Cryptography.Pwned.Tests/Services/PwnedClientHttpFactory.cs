using Microsoft.AspNetCore.Mvc.Testing;

namespace Singulink.Cryptography.Pwned.Tests;

public class PwnedClientHttpFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new HttpClient();
}
