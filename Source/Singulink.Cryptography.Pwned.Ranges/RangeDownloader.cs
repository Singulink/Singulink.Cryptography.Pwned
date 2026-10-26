using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// Downloads ranges from the Have I Been Pwned range API, retrying transient failures.
/// </summary>
internal sealed class RangeDownloader
{
    private const int InitialBufferSize = 256 * 1024;
    private const int MaxResponseLength = 16 * 1024 * 1024;

    private static readonly TimeSpan _maxBackoff = TimeSpan.FromMinutes(1);

    private readonly HttpClient _httpClient;
    private readonly RangeSyncOptions _options;

    public RangeDownloader(HttpClient httpClient, RangeSyncOptions options)
    {
        _httpClient = httpClient;
        _options = options;
    }

    /// <summary>
    /// Downloads a range. Sends <c>If-None-Match</c> when <paramref name="etag"/> is set. A response that doesn't match its Content-MD5 header, or has
    /// no Content-MD5 and fewer than <paramref name="minRecordCount"/> records (Pwned Passwords only grows, so it is probably truncated), is rejected
    /// and retried. A downloaded range's buffer is rented from <see cref="ArrayPool{T}.Shared"/> and must be returned by the caller.
    /// </summary>
    public async Task<DownloadResult> DownloadAsync(int prefix, string? etag, int minRecordCount, CancellationToken cancellationToken)
    {
        string url = "range/" + prefix.ToString("X5", CultureInfo.InvariantCulture);

        for (int attempt = 1; ; attempt++)
        {
            string reason;
            Exception? exception = null;
            TimeSpan? retryAfter = null;

            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(_options.RequestTimeout);

                // The client's default version only applies to requests it creates itself.
                using var request = new HttpRequestMessage(HttpMethod.Get, url) {
                    Version = _httpClient.DefaultRequestVersion,
                    VersionPolicy = _httpClient.DefaultVersionPolicy,
                };

                if (etag is not null)
                    request.Headers.TryAddWithoutValidation("If-None-Match", etag);

                using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);

                if (response.StatusCode is HttpStatusCode.OK)
                    return await ReadRangeAsync(response, minRecordCount, timeout.Token);

                if (response.StatusCode is HttpStatusCode.NotModified && etag is not null)
                    return DownloadResult.NotModified;

                reason = string.Create(CultureInfo.InvariantCulture, $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}");

                if (!IsTransient(response.StatusCode))
                    return DownloadResult.Failed(reason, null);

                retryAfter = GetRetryAfter(response.Headers.RetryAfter, _options.TimeProvider.GetUtcNow());
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException ex)
            {
                reason = "The request timed out.";
                exception = ex;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException)
            {
                reason = ex.Message;
                exception = ex;
            }

            if (attempt >= _options.MaxAttempts)
                return DownloadResult.Failed(reason, exception);

            await Task.Delay(GetRetryDelay(attempt, retryAfter), _options.TimeProvider, cancellationToken);
        }
    }

    /// <summary>
    /// Gets how long to wait before the next attempt: the server's Retry-After if it sent one, otherwise exponential backoff with jitter.
    /// </summary>
    internal TimeSpan GetRetryDelay(int attempt, TimeSpan? retryAfter)
    {
        if (retryAfter is { } value)
            return value > _options.MaxRetryAfter ? _options.MaxRetryAfter : value;

        double backoff = Math.Min(_options.RetryDelay.TotalMilliseconds * Math.Pow(2, attempt - 1), _maxBackoff.TotalMilliseconds);

#pragma warning disable CA5394 // Do not use insecure randomness (jitter only)
        return TimeSpan.FromMilliseconds(backoff * (1 + (Random.Shared.NextDouble() * 0.25)));
#pragma warning restore CA5394
    }

    internal static TimeSpan? GetRetryAfter(RetryConditionHeaderValue? header, DateTimeOffset now)
    {
        TimeSpan? delay = header switch {
            { Delta: { } delta } => delta,
            { Date: { } date } => date - now,
            _ => null,
        };

        return delay < TimeSpan.Zero ? TimeSpan.Zero : delay;
    }

    private static bool IsTransient(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests || (int)statusCode >= 500;

    private static async Task<DownloadResult> ReadRangeAsync(HttpResponseMessage response, int minRecordCount, CancellationToken cancellationToken)
    {
        string? etag = response.Headers.NonValidated.TryGetValues("ETag", out HeaderStringValues values) ? values.ToString() : null;

        byte[] text = ArrayPool<byte>.Shared.Rent(InitialBufferSize);
        byte[]? records = null;

        try
        {
            int length = 0;

            using (Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken))
            {
                while (true)
                {
                    if (length == text.Length)
                    {
                        if (text.Length >= MaxResponseLength)
                            throw new InvalidDataException("The range response is too large.");

                        byte[] larger = ArrayPool<byte>.Shared.Rent(Math.Min(text.Length * 2, MaxResponseLength));
                        text.AsSpan(0, length).CopyTo(larger);
                        ArrayPool<byte>.Shared.Return(text);
                        text = larger;
                    }

                    int read = await stream.ReadAsync(text.AsMemory(length), cancellationToken);

                    if (read is 0)
                        break;

                    length += read;
                }
            }

            // Have I Been Pwned sends the MD5 of the uncompressed body.
            byte[]? md5 = response.Content.Headers.ContentMD5;

#pragma warning disable CA5351 // Do not use broken cryptographic algorithms (only checks the response against its header)
            if (md5 is not null && !MD5.HashData(text.AsSpan(0, length)).AsSpan().SequenceEqual(md5))
                throw new InvalidDataException("The range response doesn't match its Content-MD5 header.");
#pragma warning restore CA5351

            records = ArrayPool<byte>.Shared.Rent(RangeFile.HeaderSize + RangeParser.GetMaxRecordBytes(length));
            int recordCount = RangeParser.Parse(text.AsSpan(0, length), records.AsSpan(RangeFile.HeaderSize));

            if (md5 is null && recordCount < minRecordCount)
            {
                string message = string.Create(
                    CultureInfo.InvariantCulture,
                    $"The range response has {recordCount} records, fewer than the {minRecordCount} stored, so it may be truncated.");

                throw new InvalidDataException(message);
            }

            var result = DownloadResult.Downloaded(records, recordCount, etag, length);
            records = null;
            return result;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(text);

            if (records is not null)
                ArrayPool<byte>.Shared.Return(records);
        }
    }
}

internal enum DownloadOutcome
{
    NotModified,
    Downloaded,
    Failed,
}

internal sealed class DownloadResult
{
    public static readonly DownloadResult NotModified = new(DownloadOutcome.NotModified);

    private DownloadResult(DownloadOutcome outcome)
    {
        Outcome = outcome;
    }

    public DownloadOutcome Outcome { get; }

    /// <summary>
    /// Gets the parsed records, after <see cref="RangeFile.HeaderSize"/> bytes of space for the header.
    /// </summary>
    public byte[]? Buffer { get; private init; }

    public int RecordCount { get; private init; }

    public string? ETag { get; private init; }

    public int ResponseLength { get; private init; }

    public string? FailureReason { get; private init; }

    public Exception? Exception { get; private init; }

    public static DownloadResult Downloaded(byte[] buffer, int recordCount, string? etag, int responseLength) => new(DownloadOutcome.Downloaded) {
        Buffer = buffer,
        RecordCount = recordCount,
        ETag = etag,
        ResponseLength = responseLength,
    };

    public static DownloadResult Failed(string reason, Exception? exception) => new(DownloadOutcome.Failed) {
        FailureReason = reason,
        Exception = exception,
    };
}
