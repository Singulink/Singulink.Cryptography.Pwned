using Singulink.Net.Http.Api;

namespace Singulink.Cryptography.Pwned.Service;

/// <summary>
/// Adds the service's error responses, which are plain text, to the OpenAPI metadata of endpoints.
/// </summary>
internal static class ErrorResponseMetadata
{
    private const string RetryAfter = "The `Retry-After` header has the number of seconds to wait before trying again.";

    /// <summary>
    /// Adds a 400 response with the specified description.
    /// </summary>
    public static RouteHandlerBuilder ProducesBadRequest(this RouteHandlerBuilder builder, string description) =>
        builder.ProducesText(StatusCodes.Status400BadRequest, description);

    /// <summary>
    /// Adds a 404 response with the specified error code and description.
    /// </summary>
    public static RouteHandlerBuilder ProducesNotFound(this RouteHandlerBuilder builder, string errorCode, string description) =>
        builder.ProducesText(StatusCodes.Status404NotFound, $"`[{errorCode}]` {description}");

    /// <summary>
    /// Adds the 429 response of the rate limit, and a 503 response with the specified causes and the cause that applies to every endpoint: Cloudflare's IP
    /// ranges aren't available yet. Each cause is described with its error code.
    /// </summary>
    public static RouteHandlerBuilder ProducesServiceErrors(this RouteHandlerBuilder builder, params (string ErrorCode, string Description)[] unavailable)
    {
        string rateLimited = $"`[{ApiErrorCodes.RateLimited}]` The client's address made too many requests. {RetryAfter}";
        builder.ProducesText(StatusCodes.Status429TooManyRequests, rateLimited);

        string[] paragraphs = [
            .. unavailable.Select(cause => $"`[{cause.ErrorCode}]` {cause.Description}"),
            $"`[{ApiErrorCodes.CloudflareRangesUnavailable}]` The service is starting: it doesn't have Cloudflare's IP ranges yet.",
            RetryAfter,
        ];

        return builder.ProducesText(StatusCodes.Status503ServiceUnavailable, string.Join("\n\n", paragraphs));
    }

    private static RouteHandlerBuilder ProducesText(this RouteHandlerBuilder builder, int statusCode, string description) =>
        builder.WithMetadata(new ProducesResponseTypeMetadata(statusCode, typeof(string), ["text/plain"]) { Description = description });
}
