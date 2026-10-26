namespace Singulink.Cryptography.Pwned.Tests;

/// <summary>
/// Tests the client against the live service at https://pwned.singulink.com. They don't run by default (see README).
/// </summary>
[TestClass]
[TestCategory("Live")]
public class CheckPasswordTests
{
    private static readonly PwnedClient _client = new(new Uri("https://pwned.singulink.com/"));

    [TestMethod]
    public async Task GetBreachCount_PasswordNotInTheData_ReturnsZero()
    {
        (await _client.GetBreachCountAsync("dsjadjbsa")).ShouldBe(0);
    }

    [TestMethod]
    public async Task GetBreachCount_PasswordInTheData_ReturnsCount()
    {
        (await _client.GetBreachCountAsync("1234")).ShouldBeGreaterThan(0);
    }
}
