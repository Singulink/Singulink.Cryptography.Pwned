using Microsoft.Extensions.Options;
using Singulink.Cryptography.Pwned.Ranges;

namespace Singulink.Cryptography.Pwned.Service;

/// <summary>
/// Service options, bound from the "Pwned" configuration section.
/// </summary>
public sealed class PwnedOptions
{
    public const string SectionName = "Pwned";

    /// <summary>
    /// Gets or sets the folder for the range files. Relative paths are resolved against the content root. Required: it has no default.
    /// </summary>
    public string? DataDirectory { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this instance syncs the data folder: downloads every range and checks them all for changes every <see
    /// cref="SyncInterval"/>. Turn it off on instances that share a data folder with one that syncs it.
    /// </summary>
    public bool SyncEnabled { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether lookups download ranges that aren't stored, are invalid or can't be read, answer from the download and
    /// store it. Turn it off on instances that must never call out, such as ones that share a read-only data folder kept up to date by another instance.
    /// </summary>
    public bool OnDemandDownloadEnabled { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the <c>/CheckPassword</c> endpoint is mapped. It takes the password itself, unhashed, in its query string,
    /// so that the service can be tried out in its Swagger UI; the client sends the password's hash to <c>/CheckPasswordHash</c> instead. When off, the
    /// endpoint doesn't exist and isn't in the OpenAPI document. Default is <see langword="true"/>.
    /// </summary>
    public bool CheckPasswordEndpointEnabled { get; set; } = true;

    /// <summary>
    /// Gets or sets how often all ranges are checked for changes.
    /// </summary>
    public TimeSpan SyncInterval { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// Gets or sets how long to wait before trying again after a pass fails or leaves ranges missing.
    /// </summary>
    public TimeSpan RetryInterval { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Gets or sets the number of ranges a sync pass downloads in parallel.
    /// </summary>
    public int DownloadConcurrency { get; set; } = RangeSyncOptions.DefaultDownloadConcurrency;

    /// <summary>
    /// Gets or sets the number of prefixes used. Tests set this to use only the first few ranges.
    /// </summary>
    internal int PrefixCount { get; set; } = RangeFile.TotalPrefixes;
}

internal sealed class PwnedOptionsValidator : IValidateOptions<PwnedOptions>
{
    private static readonly TimeSpan _maxInterval = TimeSpan.FromDays(365);

    public ValidateOptionsResult Validate(string? name, PwnedOptions options)
    {
        List<string> failures = [];

        if (string.IsNullOrWhiteSpace(options.DataDirectory))
        {
            failures.Add(
                "The Pwned:DataDirectory setting is required. Set it to the folder for the password range files (about 50 GB), " +
                "for example with the Pwned__DataDirectory environment variable.");
        }

        if (options.SyncInterval <= TimeSpan.Zero || options.SyncInterval > _maxInterval)
            failures.Add("The Pwned:SyncInterval setting must be between 00:00:01 and 365.00:00:00.");

        if (options.RetryInterval <= TimeSpan.Zero || options.RetryInterval > _maxInterval)
            failures.Add("The Pwned:RetryInterval setting must be between 00:00:01 and 365.00:00:00.");

        if (options.DownloadConcurrency is < 1 or > RangeSyncOptions.MaxDownloadConcurrency)
            failures.Add($"The Pwned:DownloadConcurrency setting must be between 1 and {RangeSyncOptions.MaxDownloadConcurrency}.");

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
