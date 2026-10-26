using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Singulink.Cryptography.Pwned;
using Singulink.Cryptography.Pwned.Ranges;
using Singulink.Cryptography.Pwned.Service;
using Singulink.Net.Http.Api;
using Singulink.Net.Http.Api.Service;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(swaggerOptions => swaggerOptions.OperationFilter<ResponseDescriptionFilter>());

builder.Services.AddPwnedRanges(builder.Configuration);
builder.Services.AddPwnedApi(builder.Configuration);

WebApplication app = builder.Build();

// First, so that everything after it sees the client's address and scheme rather than Cloudflare's.
app.UseCloudflareForwarding();
app.UseApiResponseHandling();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseRateLimiter();

app.MapGet("/", () => Results.Redirect("/swagger"))
    .ExcludeFromDescription();

(string, string)[] lookupUnavailable = [
    (PwnedErrorCodes.HibpUnavailable, "The password hash's range isn't stored and couldn't be downloaded from Have I Been Pwned."),
    (PwnedErrorCodes.RangeNotDownloaded, "The password hash's range isn't stored, and downloading ranges for lookups is turned off."),
];

const string NotFoundDescription = "The password isn't in the Pwned Passwords data.";

// The options are validated here, before the service starts, so a missing data directory fails here with the same error.
if (app.Services.GetRequiredService<IOptions<PwnedOptions>>().Value.CheckPasswordEndpointEnabled)
{
    app.MapGet("/CheckPassword", CheckPasswordAsync)
        .WithDescription("Takes the password itself, unhashed, in the query string, to try the service out. Clients send its hash to /CheckPasswordHash.")
        .Produces<CheckPasswordResult>()
        .ProducesNotFound(PwnedErrorCodes.PasswordNotFound, NotFoundDescription)
        .ProducesBadRequest("The password is missing.")
        .ProducesServiceErrors(lookupUnavailable);
}

app.MapGet("/CheckPasswordHash", CheckPasswordHashAsync)
    .Produces<CheckPasswordResult>()
    .ProducesNotFound(PwnedErrorCodes.PasswordNotFound, NotFoundDescription)
    .ProducesBadRequest("The password hash is missing, or it isn't 40 hex digits.")
    .ProducesServiceErrors(lookupUnavailable);

app.MapGet("/Status", GetStatus)
    .Produces<ServiceStatus>()
    .ProducesServiceErrors();

app.Run();

static async Task<IResult> CheckPasswordAsync(
    string password, RangeStore store, RangeFetcher fetcher, IOptions<PwnedOptions> options, HttpContext context)
{
    byte[] hash = SHA1.HashData(Encoding.UTF8.GetBytes(password));
    return await CheckPasswordHashImplAsync(hash, store, fetcher, options.Value, context);
}

static async Task<IResult> CheckPasswordHashAsync(
    string passwordHash, RangeStore store, RangeFetcher fetcher, IOptions<PwnedOptions> options, HttpContext context)
{
    passwordHash = passwordHash.Trim().ToUpperInvariant();

    if (passwordHash.Length != 40 || !passwordHash.All(c => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
        throw new BadRequestApiException("Password hash should be 40 hex characters.");

    return await CheckPasswordHashImplAsync(Convert.FromHexString(passwordHash), store, fetcher, options.Value, context);
}

static async Task<IResult> CheckPasswordHashImplAsync(byte[] hash, RangeStore store, RangeFetcher fetcher, PwnedOptions options, HttpContext context)
{
    RangeLookupResult result;

    try
    {
        result = options.OnDemandDownloadEnabled
            ? await fetcher.LookupAsync(hash, context.RequestAborted)
            : await store.LookupAsync(hash, context.RequestAborted);
    }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
    {
        // The client is gone. A range download it was waiting for continues and is still stored.
        return Results.Empty;
    }

    switch (result.Status)
    {
        case RangeLookupStatus.Found:
            return TypedResults.Ok<CheckPasswordResult>(new(result.Count));
        case RangeLookupStatus.NotFound:
            // The client returns null for this error code only, so that other 404 responses, such as from a wrong address, aren't taken for it.
            throw new NotFoundApiException("The password isn't in the Pwned Passwords data.") { ErrorCode = PwnedErrorCodes.PasswordNotFound };
        default:
            // The client shows the message to the caller. Clients up to 2.0 show the error code in front of it.
            (string errorCode, string message) = options.OnDemandDownloadEnabled
                ? (PwnedErrorCodes.HibpUnavailable, "The password hash's range couldn't be downloaded from Have I Been Pwned. Please try again later.")
                : (PwnedErrorCodes.RangeNotDownloaded, "The password hash's range hasn't been downloaded yet. Please try again later.");

            throw new ServiceUnavailableApiException(message) { ErrorCode = errorCode, RetryAfter = TimeSpan.FromMinutes(1) };
    }
}

static ServiceStatus GetStatus(
    RangeStore store, RangeSynchronizer synchronizer, RangeSyncService syncService, RangeFetcher fetcher, IOptions<PwnedOptions> options)
{
    RangeSyncProgress? currentPass = synchronizer.CurrentPass;

    return new ServiceStatus {
        RangesStored = store.StoredRanges,
        TotalRanges = store.TotalRanges,
        SyncEnabled = options.Value.SyncEnabled,
        SyncRunning = currentPass is not null,
        CurrentPass = currentPass,
        LastCompletedPass = TryReadLastCompletedPass(store),
        NextPass = syncService.NextPass,
        OnDemandDownloadEnabled = options.Value.OnDemandDownloadEnabled,
        OnDemandDownloads = fetcher.Downloads,
        OnDemandFailures = fetcher.Failures,
    };
}

static DateTimeOffset? TryReadLastCompletedPass(RangeStore store)
{
    try
    {
        return store.ReadSyncState().LastPassCompleted;
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        return null;
    }
}
