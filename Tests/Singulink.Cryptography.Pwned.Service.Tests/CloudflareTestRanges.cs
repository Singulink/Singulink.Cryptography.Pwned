namespace Singulink.Cryptography.Pwned.Service.Tests;

/// <summary>
/// Gives test hosts Cloudflare's IP ranges without downloading them: downloads are turned off, and the ranges are read from the saved copy in the data
/// folder.
/// </summary>
internal static class CloudflareTestRanges
{
    /// <summary>
    /// Gets an address in the ranges, as a Cloudflare server would connect from.
    /// </summary>
    public static IPAddress CloudflareAddress { get; } = IPAddress.Parse("173.245.48.1");

    /// <summary>
    /// Adds the setting that turns downloads off to the specified settings, and writes the saved copy into the data folder, unless
    /// <paramref name="writeSavedCopy"/> is <see langword="false"/>.
    /// </summary>
    public static void Use(Dictionary<string, string?> settings, string dataPath, bool writeSavedCopy = true)
    {
        settings["Cloudflare:DownloadRanges"] = "false";

        if (writeSavedCopy)
        {
            string path = Path.Combine(dataPath, ServiceCollectionExtensions.CloudflareRangesFileName);
            File.WriteAllText(path, "173.245.48.0/20\n103.21.244.0/22\n2400:cb00::/32\n2606:4700::/32\n# end\n");
        }
    }
}
