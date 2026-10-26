using System.Net;
using System.Text;
using Singulink.Net.Http.Api.Client;

namespace Singulink.Cryptography.Pwned.Tests;

/// <summary>
/// Tests the requests the client sends and how it reads the responses, which a fake handler sends, so they don't need the service.
/// </summary>
[TestClass]
public class ResponseTests
{
    // The SHA-1 hash of the UTF-8 bytes of "password".
    private const string PasswordHash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private static readonly Uri BaseAddress = new("https://pwned.example.com/");

    [TestMethod]
    public async Task GetBreachCount_Found_ReturnsCount()
    {
        var handler = new FakeHandler(_ => Json("""{"count":42}"""));
        var client = new PwnedClient(BaseAddress, handler);

        (await client.GetBreachCountAsync("password")).ShouldBe(42);
    }

    [TestMethod]
    public async Task GetBreachCount_SendsTheUpperCaseSha1HashOfThePassword()
    {
        var handler = new FakeHandler(_ => Json("""{"count":1}"""));
        var client = new PwnedClient(BaseAddress, handler);

        await client.GetBreachCountAsync("password");

        handler.RequestUris.ShouldHaveSingleItem().ShouldBe(new Uri($"https://pwned.example.com/CheckPasswordHash?passwordHash={PasswordHash}"));
    }

    [TestMethod]
    public async Task GetBreachCount_PasswordNotFound_ReturnsZero()
    {
        var error = new NotFoundApiException("The password isn't in the Pwned Passwords data.") { ErrorCode = PwnedErrorCodes.PasswordNotFound };
        var client = new PwnedClient(BaseAddress, new FakeHandler(_ => ApiErrorResponse.Create(error)));

        (await client.GetBreachCountAsync("password")).ShouldBe(0);
    }

    [TestMethod]
    public async Task GetBreachCount_NotFoundWithoutTheErrorCode_Throws()
    {
        // Such as from an address that isn't the service's. With content, as responses always have on .NET Framework, whose ApiClientBase throws a
        // NullReferenceException for an error without content.
        var notFound = new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("<html>Not Found</html>", Encoding.UTF8, "text/html") };
        var client = new PwnedClient(BaseAddress, new FakeHandler(_ => notFound));

        var ex = await Should.ThrowAsync<NotFoundApiException>(() => client.GetBreachCountAsync("password"));
        ex.ErrorCode.ShouldBeNull();
    }

    [TestMethod]
    public async Task GetBreachCount_ServiceUnavailable_ThrowsWithErrorCodeAndRetryAfter()
    {
        var error = new ServiceUnavailableApiException("The password hash's range couldn't be downloaded from Have I Been Pwned. Please try again later.") {
            ErrorCode = PwnedErrorCodes.HibpUnavailable,
            RetryAfter = TimeSpan.FromMinutes(1),
        };

        var client = new PwnedClient(BaseAddress, new FakeHandler(_ => ApiErrorResponse.Create(error)));

        var ex = await Should.ThrowAsync<ServiceUnavailableApiException>(() => client.GetBreachCountAsync("password"));

        ex.Message.ShouldBe(error.Message);
        ex.ErrorCode.ShouldBe(PwnedErrorCodes.HibpUnavailable);
        ex.RetryAfter.ShouldBe(TimeSpan.FromMinutes(1));
        ApiFailures.IsTransient(ex).ShouldBeTrue();
    }

    [TestMethod]
    public async Task GetBreachCount_RateLimited_ThrowsWithRetryAfter()
    {
        var error = new TooManyRequestsApiException("Too many requests. Please wait a moment and try again.") {
            ErrorCode = ApiErrorCodes.RateLimited,
            RetryAfter = TimeSpan.FromSeconds(30),
        };

        var client = new PwnedClient(BaseAddress, new FakeHandler(_ => ApiErrorResponse.Create(error)));

        var ex = await Should.ThrowAsync<TooManyRequestsApiException>(() => client.GetBreachCountAsync("password"));

        ex.ErrorCode.ShouldBe(ApiErrorCodes.RateLimited);
        ex.RetryAfter.ShouldBe(TimeSpan.FromSeconds(30));
    }

    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Uri> RequestUris { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestUris.Add(request.RequestUri!);
            return Task.FromResult(respond(request));
        }
    }
}
