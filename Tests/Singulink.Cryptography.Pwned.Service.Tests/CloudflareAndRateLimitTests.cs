using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Singulink.Net.Http.Api.Service;

namespace Singulink.Cryptography.Pwned.Service.Tests;

/// <summary>
/// Tests the client addresses that Cloudflare forwards and the per-client rate limit, with requests from chosen addresses.
/// </summary>
[TestClass]
public sealed class CloudflareAndRateLimitTests : IDisposable
{
    private const string RejectionBody = "[rate-limited] Too many requests. Please wait a moment and try again.";

    private static readonly IPAddress CloudflareAddress = CloudflareTestRanges.CloudflareAddress;

    private static readonly IPAddress PublicClient = IPAddress.Parse("203.0.113.7");
    private static readonly IPAddress OtherPublicClient = IPAddress.Parse("198.51.100.7");

    private readonly TempFolder _folder = new();
    private readonly FakeLogger _logger = new();
    private readonly FakeRangeServer _ranges = new(0);

    public void Dispose()
    {
        _ranges.Dispose();
        _folder.Dispose();
    }

    [TestMethod]
    public async Task SavedRangesInTheDataFolder_AreUsed()
    {
        using WebApplicationFactory<Program> factory = CreateFactory();

        HttpContext context = await SendAsync(factory, IPAddress.Parse("2400:cb00::1"), forwardedFor: PublicClient);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
        context.Connection.RemoteIpAddress.ShouldBe(PublicClient);

        var options = factory.Services.GetRequiredService<IOptions<CloudflareForwardingOptions>>().Value;
        options.SavedRangesPath.ShouldBe(Path.Combine(_folder.Path, "cloudflare-ip-ranges.txt"));
        _logger.Entries.ShouldNotContain(e => e.Level >= LogLevel.Warning);
    }

    [TestMethod]
    public async Task NoRanges_RequestsAreRefusedUntilTheyAreAvailable()
    {
        // As on a first start that can't download Cloudflare's lists.
        using WebApplicationFactory<Program> factory = CreateFactory(writeSavedRanges: false);

        HttpContext context = await SendAsync(factory, PublicClient);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status503ServiceUnavailable);
        context.Response.Headers.RetryAfter.ToString().ShouldBe("10");
        (await ReadBodyAsync(context)).ShouldBe("[cloudflare-ranges-unavailable] The service is starting. Please try again shortly.");
    }

    [TestMethod]
    public async Task DirectConnection_KeepsItsAddressAndLosesCloudflareHeaders()
    {
        using WebApplicationFactory<Program> factory = CreateFactory();

        HttpContext context = await SendAsync(factory, OtherPublicClient, forwardedFor: PublicClient);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
        context.Connection.RemoteIpAddress.ShouldBe(OtherPublicClient);
        context.Request.Headers.ContainsKey("CF-Connecting-IP").ShouldBeFalse();
    }

    [TestMethod]
    public async Task PublicClients_AreLimitedSeparately()
    {
        using WebApplicationFactory<Program> factory = CreateFactory(new() { ["RateLimits:PermitLimit"] = "3" });

        for (int i = 0; i < 3; i++)
            (await SendAsync(factory, PublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status200OK);

        HttpContext rejected = await SendAsync(factory, PublicClient);

        rejected.Response.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
        rejected.Response.ContentType.ShouldBe("text/plain; charset=utf-8; format=error-code");
        rejected.Response.Headers.RetryAfter.ToString().ShouldBe("30");
        (await ReadBodyAsync(rejected)).ShouldBe(RejectionBody);

        (await SendAsync(factory, OtherPublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
    }

    [TestMethod]
    public async Task DefaultLimit_Is50RequestsPerMinute()
    {
        using WebApplicationFactory<Program> factory = CreateFactory();

        for (int i = 0; i < 50; i++)
            (await SendAsync(factory, PublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status200OK);

        (await SendAsync(factory, PublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
    }

    [TestMethod]
    [DataRow("10.1.2.3")]
    [DataRow("172.16.0.9")]
    [DataRow("192.168.1.20")]
    [DataRow("127.0.0.1")]
    [DataRow("::1")]
    [DataRow("fd00::5")]
    [DataRow("::ffff:10.1.2.3")]
    public async Task PrivateClients_AreExempt(string address)
    {
        using WebApplicationFactory<Program> factory = CreateFactory(new() { ["RateLimits:PermitLimit"] = "3" });

        for (int i = 0; i < 10; i++)
            (await SendAsync(factory, IPAddress.Parse(address))).Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
    }

    [TestMethod]
    public async Task ClientsThroughCloudflare_AreLimitedByTheirOwnAddress()
    {
        using WebApplicationFactory<Program> factory = CreateFactory(new() { ["RateLimits:PermitLimit"] = "2" });

        for (int i = 0; i < 2; i++)
            (await SendAsync(factory, CloudflareAddress, forwardedFor: PublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status200OK);

        (await SendAsync(factory, CloudflareAddress, forwardedFor: PublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
        (await SendAsync(factory, CloudflareAddress, forwardedFor: OtherPublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status200OK);

        // An internal app that reaches the service through Cloudflare from a private address is exempt too.
        for (int i = 0; i < 5; i++)
        {
            HttpContext context = await SendAsync(factory, CloudflareAddress, forwardedFor: IPAddress.Parse("10.0.0.8"));
            context.Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
        }
    }

    [TestMethod]
    public async Task ExemptNetworksFromConfiguration_AreExempt()
    {
        using WebApplicationFactory<Program> factory = CreateFactory(new() {
            ["RateLimits:PermitLimit"] = "1",
            ["RateLimits:ExemptNetworks:0"] = "203.0.113.0/24",
        });

        for (int i = 0; i < 5; i++)
            (await SendAsync(factory, PublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status200OK);

        (await SendAsync(factory, OtherPublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
        (await SendAsync(factory, OtherPublicClient)).Response.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
    }

    private static Task<HttpContext> SendAsync(WebApplicationFactory<Program> factory, IPAddress remoteAddress, IPAddress? forwardedFor = null)
    {
        return factory.Server.SendAsync(context => {
            context.Request.Method = HttpMethods.Get;
            context.Request.Scheme = "https";
            context.Request.Host = new HostString("localhost");
            context.Request.Path = "/Status";
            context.Connection.RemoteIpAddress = remoteAddress;

            if (forwardedFor is not null)
                context.Request.Headers["CF-Connecting-IP"] = forwardedFor.ToString();
        });
    }

    private static async Task<string> ReadBodyAsync(HttpContext context)
    {
        using var reader = new StreamReader(context.Response.Body);
        return await reader.ReadToEndAsync();
    }

    private WebApplicationFactory<Program> CreateFactory(Dictionary<string, string?>? settings = null, bool writeSavedRanges = true)
    {
        Dictionary<string, string?> config = new() {
            ["Pwned:DataDirectory"] = _folder.Path,
            ["Pwned:SyncEnabled"] = "false",
        };

        CloudflareTestRanges.Use(config, _folder.Path, writeSavedRanges);

        foreach ((string key, string? value) in settings ?? [])
            config[key] = value;

        // Half a minute into a window, so rate limit windows don't end during a test.
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 26, 12, 0, 30, TimeSpan.Zero));

        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder => {
            builder.ConfigureAppConfiguration((_, configBuilder) => configBuilder.AddInMemoryCollection(config));
            builder.ConfigureLogging(logging => logging.ClearProviders().AddProvider(new FakeLoggerProvider(_logger.Collector)));

            builder.ConfigureTestServices(services => {
                services.AddSingleton<TimeProvider>(time);
                services.AddHttpClient(RangeHttpClient.Name).ConfigurePrimaryHttpMessageHandler(() => _ranges);
            });
        });
    }
}
