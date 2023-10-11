using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;

namespace Singulink.Cryptography.Pwned.Tests;

public class PwnedClientHttpFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name)
    {
        var appFactory = new WebApplicationFactory<Program>();
        return appFactory.CreateClient();
    }
}
