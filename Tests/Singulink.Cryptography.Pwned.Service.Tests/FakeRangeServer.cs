using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Singulink.Cryptography.Pwned.Service.Tests;

/// <summary>
/// Serves generated ranges like the Have I Been Pwned range API, without network access.
/// </summary>
internal sealed class FakeRangeServer : HttpMessageHandler
{
    private readonly ConcurrentDictionary<int, ServedRange> _ranges = new();
    private readonly ConcurrentDictionary<int, int> _requestCounts = new();
    private int _version;

    public FakeRangeServer(int prefixCount, int seed = 1, int recordsPerRange = 100)
    {
        for (int prefix = 0; prefix < prefixCount; prefix++)
            SetRange(prefix, TestRanges.Generate(new Random((seed * 1_000_003) + prefix), recordsPerRange));
    }

    public ConcurrentQueue<RangeRequest> Requests { get; } = new();

    /// <summary>
    /// Gets or sets a function that returns a response to send instead of the range (or throws), or <see langword="null"/> to serve the range. It gets the
    /// prefix and the request number for that prefix, starting at 1.
    /// </summary>
    public Func<int, int, HttpResponseMessage?>? Intercept { get; set; }

    /// <summary>
    /// Gets or sets an action called for every request before it is answered.
    /// </summary>
    public Action<int>? OnRequest { get; set; }

    /// <summary>
    /// Gets or sets a function awaited for every request before it is answered, e.g. to delay it. It gets the prefix and the request's cancellation
    /// token.
    /// </summary>
    public Func<int, CancellationToken, Task>? BeforeResponse { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether ranges are served with a Content-MD5 header, like Have I Been Pwned does.
    /// </summary>
    public bool SendContentMd5 { get; set; }

    public RangeEntry[] GetEntries(int prefix) => _ranges[prefix].Entries;

    public string GetETag(int prefix) => _ranges[prefix].ETag;

    public int GetRequestCount(int prefix) => _requestCounts.GetValueOrDefault(prefix);

    public void SetRange(int prefix, RangeEntry[] entries)
    {
        int version = Interlocked.Increment(ref _version);
        string etag = string.Create(CultureInfo.InvariantCulture, $"W/\"0x8DED{version:X8}\"");
        _ranges[prefix] = new ServedRange(entries, TestRanges.ToResponse(entries), etag);
    }

    public void RemoveRange(int prefix) => _ranges.TryRemove(prefix, out _);

    public void ClearRequests()
    {
        Requests.Clear();
        _requestCounts.Clear();
    }

    public static HttpResponseMessage CreateResponse(HttpStatusCode statusCode, string? body = null)
    {
        var response = new HttpResponseMessage(statusCode);

        if (body is not null)
            response.Content = new ByteArrayContent(Encoding.ASCII.GetBytes(body));

        return response;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string path = request.RequestUri!.AbsolutePath;
        path.ShouldStartWith("/range/");

        int prefix = int.Parse(path["/range/".Length..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
        string? ifNoneMatch = request.Headers.TryGetValues("If-None-Match", out IEnumerable<string>? values) ? values.Single() : null;
        int number = _requestCounts.AddOrUpdate(prefix, 1, (_, n) => n + 1);

        Requests.Enqueue(new RangeRequest(prefix, ifNoneMatch, request.Headers.UserAgent.ToString(), request.Version));
        OnRequest?.Invoke(prefix);

        if (BeforeResponse is { } beforeResponse)
            await beforeResponse(prefix, cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();

        if (Intercept?.Invoke(prefix, number) is { } custom)
            return custom;

        if (!_ranges.TryGetValue(prefix, out ServedRange? range))
            return CreateResponse(HttpStatusCode.NotFound);

        HttpResponseMessage response;

        if (ifNoneMatch == range.ETag)
        {
            response = CreateResponse(HttpStatusCode.NotModified);
        }
        else
        {
            response = CreateResponse(HttpStatusCode.OK, range.Body);
            response.Content.Headers.ContentType = new("text/plain");

            if (SendContentMd5)
                response.Content.Headers.ContentMD5 = GetMd5(range.Body);
        }

        response.Headers.TryAddWithoutValidation("ETag", range.ETag);
        return response;
    }

#pragma warning disable CA5351 // Do not use broken cryptographic algorithms
    public static byte[] GetMd5(string body) => MD5.HashData(Encoding.ASCII.GetBytes(body));
#pragma warning restore CA5351

    private sealed record ServedRange(RangeEntry[] Entries, string Body, string ETag);
}

internal sealed record RangeRequest(int Prefix, string? IfNoneMatch, string UserAgent, Version Version);
