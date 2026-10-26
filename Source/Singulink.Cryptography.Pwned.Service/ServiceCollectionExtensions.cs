using System.Text.Json.Serialization.Metadata;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Singulink.Cryptography.Pwned.Ranges;
using Singulink.Net.Http.Api.Service;

namespace Singulink.Cryptography.Pwned.Service;

internal static class ServiceCollectionExtensions
{
    /// <summary>
    /// The configuration section of the Cloudflare forwarding options.
    /// </summary>
    public const string CloudflareSectionName = "Cloudflare";

    /// <summary>
    /// The name of the saved copy of Cloudflare's IP ranges in the data folder.
    /// </summary>
    public const string CloudflareRangesFileName = "cloudflare-ip-ranges.txt";

    /// <summary>
    /// The configuration section of the per-client rate limit.
    /// </summary>
    public const string RateLimitsSectionName = "RateLimits";

    /// <summary>
    /// The default number of requests each public client address can make per minute.
    /// </summary>
    public const int DefaultPermitLimit = 50;

    private const string UserAgentProduct = "Singulink.Cryptography.Pwned.Service";

    /// <summary>
    /// Registers the API toolkit's services: error responses in its format, the client addresses that Cloudflare forwards (with the saved copy of
    /// Cloudflare's IP ranges in the data folder), and a per-client rate limit that private addresses are exempt from.
    /// </summary>
    public static IServiceCollection AddPwnedApi(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddApiExceptionHandler();
        services.AddApiResponseHandling();
        services.AddApiJson(JsonTypeInfoResolver.Combine(PwnedJsonSerializerContext.Default, ServiceJsonSerializerContext.Default));

        services.AddCloudflareForwarding();

        services.AddOptions<CloudflareForwardingOptions>()
            .Bind(configuration.GetSection(CloudflareSectionName))
            .Configure<IOptions<PwnedOptions>, IHostEnvironment>((options, pwnedOptions, environment) => {
                if (options.SavedRangesPath is null && pwnedOptions.Value.DataDirectory is { } dataDirectory)
                {
                    string dataFolder = Path.GetFullPath(dataDirectory, environment.ContentRootPath);
                    options.SavedRangesPath = Path.Combine(dataFolder, CloudflareRangesFileName);
                }
            });

        services.AddRateLimiter(options => options.SetClientFixedWindowGlobalLimiter(limit => {
            limit.PermitLimit = DefaultPermitLimit;

            // Internal apps reach the service from private addresses.
            limit.ExemptPrivateNetworks = true;

            configuration.GetSection(RateLimitsSectionName).Bind(limit);
        }));

        return services;
    }

    public static IServiceCollection AddPwnedRanges(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<PwnedOptions>()
            .Bind(configuration.GetSection(PwnedOptions.SectionName))
            .ValidateOnStart();

        services.AddSingleton<IValidateOptions<PwnedOptions>, PwnedOptionsValidator>();
        services.TryAddSingleton(TimeProvider.System);

        // A pass makes a million requests, so the client's per-request logging is removed.
        services.AddHttpClient(RangeHttpClient.Name, client => RangeHttpClient.Configure(client, UserAgentProduct))
            .ConfigurePrimaryHttpMessageHandler(RangeHttpClient.CreateHandler)
            .RemoveAllLoggers();

        services.AddSingleton(provider => {
            PwnedOptions options = provider.GetRequiredService<IOptions<PwnedOptions>>().Value;
            string dataPath = Path.GetFullPath(options.DataDirectory!, provider.GetRequiredService<IHostEnvironment>().ContentRootPath);

            return new RangeStore(dataPath, options.PrefixCount, provider.GetRequiredService<ILogger<RangeStore>>());
        });

        services.AddSingleton(provider => {
            PwnedOptions options = provider.GetRequiredService<IOptions<PwnedOptions>>().Value;

            var syncOptions = new RangeSyncOptions {
                DownloadConcurrency = options.DownloadConcurrency,
                TimeProvider = provider.GetRequiredService<TimeProvider>(),
            };

            return new RangeSynchronizer(
                provider.GetRequiredService<RangeStore>(),
                provider.GetRequiredService<IHttpClientFactory>().CreateClient(RangeHttpClient.Name),
                provider.GetRequiredService<ILogger<RangeSynchronizer>>(),
                syncOptions);
        });

        services.AddSingleton(provider => new RangeFetcher(
            provider.GetRequiredService<RangeStore>(),
            provider.GetRequiredService<IHttpClientFactory>().CreateClient(RangeHttpClient.Name),
            provider.GetRequiredService<ILogger<RangeFetcher>>(),
            new RangeFetchOptions { TimeProvider = provider.GetRequiredService<TimeProvider>() }));

        services.AddSingleton<RangeSyncService>();
        services.AddHostedService(provider => provider.GetRequiredService<RangeSyncService>());

        return services;
    }
}
