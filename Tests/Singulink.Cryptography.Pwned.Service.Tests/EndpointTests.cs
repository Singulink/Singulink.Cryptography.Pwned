using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Singulink.Cryptography.Pwned.Client;
using Singulink.Net.Http.Api;
using Singulink.Net.Http.Api.Client;
using Singulink.Net.Http.Api.Service.Testing;

namespace Singulink.Cryptography.Pwned.Service.Tests;

[TestClass]
public sealed class EndpointTests : IDisposable
{
    private const int Prefix = 0x12345;
    private const int UnstoredPrefix = 0x54321;
    private const string DownloadFailedMessage = "The password hash's range couldn't be downloaded from Have I Been Pwned. Please try again later.";
    private const string NotDownloadedMessage = "The password hash's range hasn't been downloaded yet. Please try again later.";

    private readonly TempFolder _folder = new();
    private readonly FakeLogger _logger = new();
    private readonly RangeEntry[] _entries = TestRanges.Generate(new Random(1), 500);

    // Stands in for Have I Been Pwned in every test, so on-demand downloads never reach the network. Serves ranges 0 to 15 only.
    private readonly FakeRangeServer _server = new(16);

    public void Dispose()
    {
        _server.Dispose();
        _folder.Dispose();
    }

    [TestMethod]
    public async Task CheckPasswordHash_Found_ReturnsCount()
    {
        await WriteRangeAsync(Prefix, _entries);
        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        foreach (RangeEntry entry in _entries.Where((_, i) => i % 50 is 0))
        {
            using HttpResponseMessage response = await client.GetAsync(HashUrl(entry.GetHashHex(Prefix)));

            response.StatusCode.ShouldBe(HttpStatusCode.OK);
            (await response.Content.ReadAsStringAsync()).ShouldBe($$"""{"count":{{entry.Count}}}""");
        }
    }

    [TestMethod]
    public async Task CheckPasswordHash_LowerCaseWithWhitespace_IsFound()
    {
        await WriteRangeAsync(Prefix, _entries);
        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        using HttpResponseMessage response = await client.GetAsync(HashUrl(" " + _entries[7].GetHashHex(Prefix).ToLowerInvariant() + " "));

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [TestMethod]
    public async Task CheckPasswordHash_NotInStoredRange_Returns404()
    {
        await WriteRangeAsync(Prefix, _entries);
        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        using HttpResponseMessage response = await client.GetAsync(HashUrl(GetAbsentHashHex()));

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        response.Content.Headers.ContentType.ShouldNotBeNull().ToString().ShouldBe("text/plain; charset=utf-8; format=error-code");
        (await response.Content.ReadAsStringAsync()).ShouldBe("[password-not-found] The password isn't in the Pwned Passwords data.");
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task CheckPasswordEndpoint_IsMappedOnlyWhenEnabled(bool enabled)
    {
        using WebApplicationFactory<Program> factory = CreateFactory(settings: new() { ["Pwned:CheckPasswordEndpointEnabled"] = enabled ? "true" : "false" });
        using HttpClient client = CreateClient(factory);

        // The fake server doesn't have the range of "password", so the endpoint answers 503 when it exists.
        using HttpResponseMessage response = await client.GetAsync("/CheckPassword?password=password");
        response.StatusCode.ShouldBe(enabled ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.NotFound);

        JsonElement paths = JsonDocument.Parse(await client.GetStringAsync("/swagger/v1/swagger.json")).RootElement.GetProperty("paths");
        paths.TryGetProperty("/CheckPassword", out _).ShouldBe(enabled);
        paths.TryGetProperty("/CheckPasswordHash", out _).ShouldBeTrue();
    }

    [TestMethod]
    [DataRow("81fe8bfe87576c3ecb22426f8e5784738")]
    [DataRow("cf7462ba02ed08d001d2e979299e1b3d95ce00e!")]
    [DataRow("cf7462ba02ed08d001d2e979299e1b3d95ce00e00")]
    public async Task CheckPasswordHash_Invalid_Returns400WithMessage(string hash)
    {
        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        using HttpResponseMessage response = await client.GetAsync(HashUrl(hash));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync()).ShouldBe("Password hash should be 40 hex characters.");
    }

    [TestMethod]
    public async Task CheckPasswordHash_MissingRange_IsDownloadedOnDemand()
    {
        RangeEntry[] entries = TestRanges.Generate(new Random(2), 300);
        _server.SetRange(UnstoredPrefix, entries);

        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        using HttpResponseMessage found = await client.GetAsync(HashUrl(entries[42].GetHashHex(UnstoredPrefix)));
        using HttpResponseMessage notFound = await client.GetAsync(HashUrl(GetAbsentHashHex(entries, UnstoredPrefix)));

        found.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await found.Content.ReadAsStringAsync()).ShouldBe($$"""{"count":{{entries[42].Count}}}""");
        notFound.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        _server.Requests.ShouldHaveSingleItem().ShouldSatisfyAllConditions(
            r => r.Prefix.ShouldBe(UnstoredPrefix),
            r => r.UserAgent.ShouldStartWith("Singulink.Cryptography.Pwned.Service"));

        JsonElement status = await WaitForStatusAsync(client, s => s.GetProperty("rangesStored").ValueKind is JsonValueKind.Number &&
            s.GetProperty("rangesStored").GetInt32() is 1);

        status.GetProperty("onDemandDownloadEnabled").GetBoolean().ShouldBeTrue();
        status.GetProperty("onDemandDownloads").GetInt64().ShouldBe(1);
        status.GetProperty("onDemandFailures").GetInt64().ShouldBe(0);

        var store = new RangeStore(_folder.Path);
        store.ReadHeader(UnstoredPrefix, out string? etag, out _, checkRecords: true).ShouldBe(RangeFileStatus.Valid);
        etag.ShouldBe(_server.GetETag(UnstoredPrefix));
    }

    [TestMethod]
    public async Task CheckPasswordHash_RangeCannotBeDownloaded_Returns503WithRetryAfter()
    {
        await WriteRangeAsync(Prefix, _entries);
        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        // The fake server doesn't have this range.
        using HttpResponseMessage response = await client.GetAsync(HashUrl(_entries[0].GetHashHex(UnstoredPrefix)));

        response.StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        response.Headers.RetryAfter.ShouldNotBeNull().Delta.ShouldBe(TimeSpan.FromMinutes(1));

        response.Content.Headers.ContentType.ShouldNotBeNull().ToString().ShouldBe("text/plain; charset=utf-8; format=error-code");
        (await response.Content.ReadAsStringAsync()).ShouldBe($"[{PwnedErrorCodes.HibpUnavailable}] {DownloadFailedMessage}");
        _server.GetRequestCount(UnstoredPrefix).ShouldBe(1);

        JsonElement status = JsonDocument.Parse(await client.GetStringAsync("/Status")).RootElement;
        status.GetProperty("onDemandDownloads").GetInt64().ShouldBe(0);
        status.GetProperty("onDemandFailures").GetInt64().ShouldBe(1);
        _logger.Entries.ShouldContain(e => e.Level == LogLevel.Warning && e.Message.Contains("Range 54321 couldn't be downloaded on demand: HTTP 404"));
    }

    [TestMethod]
    public async Task CheckPasswordHash_OnDemandDownloadDisabled_Returns503WithoutDownloading()
    {
        _server.SetRange(UnstoredPrefix, _entries);
        using WebApplicationFactory<Program> factory = CreateFactory(settings: new() { ["Pwned:OnDemandDownloadEnabled"] = "false" });
        using HttpClient client = CreateClient(factory);

        using HttpResponseMessage response = await client.GetAsync(HashUrl(_entries[0].GetHashHex(UnstoredPrefix)));

        response.StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        response.Headers.RetryAfter.ShouldNotBeNull().Delta.ShouldBe(TimeSpan.FromMinutes(1));
        (await response.Content.ReadAsStringAsync()).ShouldBe($"[{PwnedErrorCodes.RangeNotDownloaded}] {NotDownloadedMessage}");
        _server.Requests.ShouldBeEmpty();

        JsonElement status = JsonDocument.Parse(await client.GetStringAsync("/Status")).RootElement;
        status.GetProperty("onDemandDownloadEnabled").GetBoolean().ShouldBeFalse();
    }

    [TestMethod]
    public async Task CheckPassword_HashesPasswordAndLooksItUp()
    {
        byte[] hash = SHA1.HashData(Encoding.UTF8.GetBytes("password"));
        int prefix = RangeFile.GetPrefix(hash);
        byte[] suffix = new byte[RangeFile.SuffixSize];
        RangeFile.GetSuffix(hash, suffix);

        RangeEntry[] entries = [.. _entries.Append(new RangeEntry(suffix, 9_545_824)).DistinctBy(e => e.SuffixHex).Order(EntryComparer)];
        await WriteRangeAsync(prefix, entries);

        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        using HttpResponseMessage found = await client.GetAsync("/CheckPassword?password=password");
        using HttpResponseMessage notFound = await client.GetAsync("/CheckPassword?password=" + GetPasswordInRange(prefix, entries));
        using HttpResponseMessage unavailable = await client.GetAsync("/CheckPassword?password=1234");

        found.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await found.Content.ReadAsStringAsync()).ShouldBe("""{"count":9545824}""");
        notFound.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        unavailable.StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
    }

    [TestMethod]
    public async Task Client_WorksAgainstService()
    {
        (int prefix, RangeEntry[] entries) = await WriteRangeWithPasswordAsync("password", 9_545_824);
        using WebApplicationFactory<Program> factory = CreateFactory();
        var pwned = CreatePwnedClient(factory);

        (await pwned.GetBreachCountAsync("password")).ShouldBe(9_545_824);
        (await pwned.GetBreachCountAsync(GetPasswordInRange(prefix, entries))).ShouldBe(0);

        // The fake server doesn't have the range of "1234", so it can't be downloaded.
        var unavailable = await Should.ThrowAsync<ServiceUnavailableApiException>(() => pwned.GetBreachCountAsync("1234"));
        unavailable.Message.ShouldBe(DownloadFailedMessage);
        unavailable.ErrorCode.ShouldBe(PwnedErrorCodes.HibpUnavailable);
        unavailable.RetryAfter.ShouldBe(TimeSpan.FromMinutes(1));
        ApiFailures.IsTransient(unavailable).ShouldBeTrue();
    }

    [TestMethod]
    public async Task Client_SendsTheHashOfThePassword()
    {
        await WriteRangeWithPasswordAsync("password", 9_545_824);

        using WebApplicationFactory<Program> factory = CreateFactory();
        var faults = new FaultInjectionHandler(factory.Server.CreateHandler());
        var pwned = new PwnedClient(new Uri("https://localhost/"), faults);

        (await pwned.GetBreachCountAsync("password")).ShouldBe(9_545_824);

        string expected = "/CheckPasswordHash?passwordHash=" + Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes("password")));
        faults.Requests.ShouldHaveSingleItem().RequestUri.ShouldNotBeNull().PathAndQuery.ShouldBe(expected);
    }

    [TestMethod]
    public async Task Client_ConnectionFailure_IsTransient()
    {
        using WebApplicationFactory<Program> factory = CreateFactory();
        var faults = new FaultInjectionHandler(factory.Server.CreateHandler()).FailBeforeSending(_ => true);
        var pwned = new PwnedClient(new Uri("https://localhost/"), faults);

        var ex = await Should.ThrowAsync<HttpRequestException>(() => pwned.GetBreachCountAsync("password"));
        ApiFailures.IsTransient(ex).ShouldBeTrue();
    }

    [TestMethod]
    public async Task Status_SyncDisabled_ReportsStoredRangesAndLastPass()
    {
        await WriteRangeAsync(1, _entries);
        await WriteRangeAsync(2, _entries);
        await WriteRangeAsync(0xFFFFF, _entries);

        var lastPass = new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
        await new RangeStore(_folder.Path).WriteSyncStateAsync(new() { LastPassStarted = lastPass.AddHours(-1), LastPassCompleted = lastPass }, default);

        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        JsonElement status = await WaitForStatusAsync(client, s => s.GetProperty("rangesStored").ValueKind is JsonValueKind.Number);

        status.GetProperty("rangesStored").GetInt32().ShouldBe(3);
        status.GetProperty("totalRanges").GetInt32().ShouldBe(1 << 20);
        status.GetProperty("syncEnabled").GetBoolean().ShouldBeFalse();
        status.GetProperty("syncRunning").GetBoolean().ShouldBeFalse();
        status.GetProperty("currentPass").ValueKind.ShouldBe(JsonValueKind.Null);
        status.GetProperty("lastCompletedPass").GetDateTimeOffset().ShouldBe(lastPass);
        status.GetProperty("nextPass").ValueKind.ShouldBe(JsonValueKind.Null);
        status.GetProperty("onDemandDownloadEnabled").GetBoolean().ShouldBeTrue();
        status.GetProperty("onDemandDownloads").GetInt64().ShouldBe(0);
        status.GetProperty("onDemandFailures").GetInt64().ShouldBe(0);
    }

    [TestMethod]
    public async Task SyncEnabled_DownloadsRangesThenAnswersLookups()
    {
        using WebApplicationFactory<Program> factory = CreateFactory(
            syncEnabled: true, configureServices: services => services.PostConfigure<PwnedOptions>(o => o.PrefixCount = 16));

        using HttpClient client = CreateClient(factory);

        JsonElement status = await WaitForStatusAsync(client, s => s.GetProperty("lastCompletedPass").ValueKind is not JsonValueKind.Null);

        status.GetProperty("rangesStored").GetInt32().ShouldBe(16);
        status.GetProperty("totalRanges").GetInt32().ShouldBe(16);
        status.GetProperty("syncEnabled").GetBoolean().ShouldBeTrue();
        _server.Requests.Count.ShouldBe(16);
        _server.Requests.ShouldAllBe(r => r.UserAgent.StartsWith("Singulink.Cryptography.Pwned.Service"));

        // The next full pass is scheduled a week after this one started.
        status = await WaitForStatusAsync(client, s => s.GetProperty("nextPass").ValueKind is not JsonValueKind.Null);
        status.GetProperty("nextPass").GetDateTimeOffset().ShouldBeGreaterThan(DateTimeOffset.UtcNow.AddDays(6));

        RangeEntry entry = _server.GetEntries(3)[10];
        using HttpResponseMessage found = await client.GetAsync(HashUrl(entry.GetHashHex(3)));

        // Beyond the test's prefix count, so it isn't downloaded on demand.
        using HttpResponseMessage unavailable = await client.GetAsync(HashUrl(entry.GetHashHex(16)));

        found.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await found.Content.ReadAsStringAsync()).ShouldBe($$"""{"count":{{entry.Count}}}""");
        unavailable.StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        _server.Requests.Count.ShouldBe(16);
    }

    [TestMethod]
    public async Task SyncError_IsRetriedWithoutStoppingTheService()
    {
        // A directory where the sync state file should be makes reading the state throw.
        Directory.CreateDirectory(Path.Combine(_folder.Path, RangeStore.SyncStateFileName));

        using WebApplicationFactory<Program> factory = CreateFactory(
            syncEnabled: true, configureServices: services => services.PostConfigure<PwnedOptions>(o => o.PrefixCount = 16));

        using HttpClient client = CreateClient(factory);

        JsonElement status = await WaitForStatusAsync(client, s => s.GetProperty("nextPass").ValueKind is not JsonValueKind.Null);

        status.GetProperty("nextPass").GetDateTimeOffset().ShouldBeGreaterThan(DateTimeOffset.UtcNow.AddMinutes(10));
        status.GetProperty("lastCompletedPass").ValueKind.ShouldBe(JsonValueKind.Null);
        _server.Requests.ShouldBeEmpty();

        await Task.Delay(300);
        _logger.Count("Range sync failed").ShouldBe(1);

        using HttpResponseMessage response = await client.GetAsync(HashUrl("abc"));
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [TestMethod]
    public async Task OpenApi_DescribesErrorResponsesWithTheirErrorCodes()
    {
        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        JsonElement paths = JsonDocument.Parse(await client.GetStringAsync("/swagger/v1/swagger.json")).RootElement.GetProperty("paths");

        foreach (string path in (string[])["/CheckPassword", "/CheckPasswordHash"])
        {
            JsonElement responses = paths.GetProperty(path).GetProperty("get").GetProperty("responses");

            responses.EnumerateObject().Select(r => r.Name).ShouldBe(["200", "400", "404", "429", "503"], ignoreOrder: true);
            GetDescription(responses, "400").ShouldNotBeNullOrEmpty();
            GetDescription(responses, "404").ShouldContain("`[password-not-found]`");
            GetDescription(responses, "429").ShouldContain("`[rate-limited]`");
            GetDescription(responses, "503").ShouldSatisfyAllConditions(
                d => d.ShouldContain("`[hibp-unavailable]`"),
                d => d.ShouldContain("`[range-not-downloaded]`"),
                d => d.ShouldContain("`[cloudflare-ranges-unavailable]`"),
                d => d.ShouldContain("Retry-After"));
        }

        JsonElement statusResponses = paths.GetProperty("/Status").GetProperty("get").GetProperty("responses");

        statusResponses.EnumerateObject().Select(r => r.Name).ShouldBe(["200", "429", "503"], ignoreOrder: true);
        GetDescription(statusResponses, "503").ShouldContain("`[cloudflare-ranges-unavailable]`");
        GetDescription(statusResponses, "503").ShouldNotContain("hibp-unavailable");

        static string GetDescription(JsonElement responses, string statusCode) =>
            responses.GetProperty(statusCode).GetProperty("description").GetString().ShouldNotBeNull();
    }

    [TestMethod]
    public async Task TestHost_LogsOnlyToTheTestLogger()
    {
        await WriteRangeAsync(Prefix, _entries);
        using WebApplicationFactory<Program> factory = CreateFactory();
        using HttpClient client = CreateClient(factory);

        using HttpResponseMessage response = await client.GetAsync(HashUrl(_entries[0].GetHashHex(Prefix)));

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        factory.Services.GetServices<ILoggerProvider>().ShouldAllBe(p => p is FakeLoggerProvider);
        _logger.Entries.ShouldNotContain(e => e.Level >= LogLevel.Warning);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow(null)]
    public async Task MissingDataDirectory_FailsAtStartupWithClearMessage(string? dataDirectory)
    {
        Exception ex = await StartWithFailureAsync(new() { ["Pwned:DataDirectory"] = dataDirectory });

        GetMessages(ex).ShouldContain(m => m.Contains("The Pwned:DataDirectory setting is required.") && m.Contains("Pwned__DataDirectory"), ex.ToString());
    }

    [TestMethod]
    public async Task InvalidOptions_FailAtStartup()
    {
        Exception ex = await StartWithFailureAsync(new() {
            ["Pwned:DownloadConcurrency"] = "0",
            ["Pwned:SyncInterval"] = "00:00:00",
        });

        string messages = string.Join(Environment.NewLine, GetMessages(ex));
        messages.ShouldContain("Pwned:DownloadConcurrency", customMessage: ex.ToString());
        messages.ShouldContain("Pwned:SyncInterval", customMessage: ex.ToString());
    }

    private static IEnumerable<string> GetMessages(Exception? ex)
    {
        for (; ex is not null; ex = ex.InnerException)
            yield return ex.Message;
    }

    private static Comparer<RangeEntry> EntryComparer { get; } = Comparer<RangeEntry>.Create((x, y) => TestRanges.SuffixComparer.Compare(x.Suffix, y.Suffix));

    private static string HashUrl(string hash) => "/CheckPasswordHash?passwordHash=" + Uri.EscapeDataString(hash);

    private static async Task<JsonElement> WaitForStatusAsync(HttpClient client, Func<JsonElement, bool> condition)
    {
        JsonElement status = default;

        for (int i = 0; i < 300; i++)
        {
            status = JsonDocument.Parse(await client.GetStringAsync("/Status")).RootElement;

            if (condition(status))
                return status;

            await Task.Delay(50);
        }

        Assert.Fail("Timed out waiting for the status: " + status);
        return status;
    }

    // Finds a password whose hash is in the given range but isn't in it.
    private static string GetPasswordInRange(int prefix, RangeEntry[] entries)
    {
        var present = entries.Select(e => e.GetHashHex(prefix)).ToHashSet();

        for (int i = 0; ; i++)
        {
            string password = "test" + i;
            byte[] hash = SHA1.HashData(Encoding.UTF8.GetBytes(password));

            if (RangeFile.GetPrefix(hash) == prefix && !present.Contains(Convert.ToHexString(hash)))
                return password;

            if (i > 10_000_000)
                throw new InvalidOperationException("No password found.");
        }
    }

    private static string GetAbsentHashHex(RangeEntry[] entries, int prefix)
    {
        var present = entries.Select(e => e.SuffixHex).ToHashSet();
        RangeEntry absent = entries.Select(e => new RangeEntry([.. e.Suffix[..^1], (byte)(e.Suffix[^1] ^ 1)], 1)).First(e => !present.Contains(e.SuffixHex));

        return absent.GetHashHex(prefix);
    }

    private string GetAbsentHashHex() => GetAbsentHashHex(_entries, Prefix);

    private Task WriteRangeAsync(int prefix, RangeEntry[] entries) => TestRanges.WriteAsync(new RangeStore(_folder.Path), prefix, entries);

    /// <summary>
    /// Writes the range of the specified password's hash, with the test's entries and the hash with the specified count.
    /// </summary>
    private async Task<(int Prefix, RangeEntry[] Entries)> WriteRangeWithPasswordAsync(string password, int count)
    {
        byte[] hash = SHA1.HashData(Encoding.UTF8.GetBytes(password));
        int prefix = RangeFile.GetPrefix(hash);
        byte[] suffix = new byte[RangeFile.SuffixSize];
        RangeFile.GetSuffix(hash, suffix);

        RangeEntry[] entries = [.. _entries.Append(new RangeEntry(suffix, count)).DistinctBy(e => e.SuffixHex).Order(EntryComparer)];
        await WriteRangeAsync(prefix, entries);

        return (prefix, entries);
    }

    private WebApplicationFactory<Program> CreateFactory(
        bool syncEnabled = false, Action<IServiceCollection>? configureServices = null, Dictionary<string, string?>? settings = null)
    {
        Dictionary<string, string?> config = GetSettings(syncEnabled, settings);

        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder => {
            builder.ConfigureAppConfiguration((_, configBuilder) => configBuilder.AddInMemoryCollection(config));

            // Only log to the test logger, not to the console, debugger or Windows event log.
            builder.ConfigureLogging(logging => logging.ClearProviders().AddProvider(new FakeLoggerProvider(_logger.Collector)));

            builder.ConfigureTestServices(services => {
                services.AddHttpClient(RangeHttpClient.Name).ConfigurePrimaryHttpMessageHandler(() => _server);
                configureServices?.Invoke(services);
            });
        });
    }

    /// <summary>
    /// Starts a host with the service's registrations that is expected to fail, and returns the exception. When startup fails, WebApplicationFactory
    /// can report that the app disposed its services instead of the startup error, depending on timing, so this starts the host on the test thread.
    /// </summary>
    private async Task<Exception> StartWithFailureAsync(Dictionary<string, string?> settings)
    {
        // An empty builder has no logging providers, so this only logs to the test logger.
        WebApplicationBuilder builder = WebApplication.CreateEmptyBuilder(new());
        builder.Configuration.AddInMemoryCollection(GetSettings(syncEnabled: false, settings));
        builder.Logging.AddProvider(new FakeLoggerProvider(_logger.Collector));
        builder.WebHost.UseTestServer();
        builder.Services.AddPwnedRanges(builder.Configuration);
        builder.Services.AddPwnedApi(builder.Configuration);

        await using WebApplication app = builder.Build();
        return await Should.ThrowAsync<Exception>(() => app.StartAsync());
    }

    private Dictionary<string, string?> GetSettings(bool syncEnabled, Dictionary<string, string?>? settings)
    {
        Dictionary<string, string?> config = new() {
            ["Pwned:DataDirectory"] = _folder.Path,
            ["Pwned:SyncEnabled"] = syncEnabled ? "true" : "false",
        };

        CloudflareTestRanges.Use(config, _folder.Path);

        foreach ((string key, string? value) in settings ?? [])
            config[key] = value;

        return config;
    }

    // HTTPS, so the HTTPS redirection middleware has nothing to do (and nothing to warn about).
    private static HttpClient CreateClient(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });

    // HTTPS, like the test clients, so the HTTPS redirection middleware has nothing to do.
    private static PwnedClient CreatePwnedClient(WebApplicationFactory<Program> factory) => new(new Uri("https://localhost/"), factory.Server.CreateHandler());
}
