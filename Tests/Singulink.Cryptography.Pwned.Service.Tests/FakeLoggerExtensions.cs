namespace Singulink.Cryptography.Pwned.Service.Tests;

/// <summary>
/// Reads what a <see cref="FakeLogger"/> collected.
/// </summary>
internal static class FakeLoggerExtensions
{
    extension(FakeLogger logger)
    {
        /// <summary>
        /// Gets the records collected so far.
        /// </summary>
        public IReadOnlyList<FakeLogRecord> Entries => logger.Collector.GetSnapshot();

        /// <summary>
        /// Gets the number of records collected so far whose message contains the specified text.
        /// </summary>
        public int Count(string text) => logger.Collector.GetSnapshot().Count(r => r.Message.Contains(text, StringComparison.Ordinal));
    }
}
