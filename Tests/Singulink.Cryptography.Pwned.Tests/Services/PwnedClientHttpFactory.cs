using Microsoft.AspNetCore.Mvc.Testing;

namespace Singulink.Cryptography.Pwned.Tests;

public class PwnedClientHttpFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name)
    {
        var appFactory = new WebApplicationFactory<Program>();
        return appFactory.CreateClient();
    }
}
