using System.Net.Http;
using Shouldly;
using Singulink.Cryptography.Pwned.Client;

namespace Singulink.Cryptography.Pwned.Tests;

[TestClass]
public class CheckPasswordTests
{
    private static readonly PwnedClient _client = new PwnedClient(new TestHttpClientFactory());

    [TestMethod]
    public async Task CheckPasswordAsync_PasswordDoesNotExist_NotFound()
    {
        var result = await _client.CheckPasswordAsync("dsjadjbsa");

        result.ShouldBeNull();
    }

    [TestMethod]
    public async Task CheckPasswordAsync_PasswordExists_ReturnsSuccess()
    {
        var result = await _client.CheckPasswordAsync("1234");

        result.ShouldNotBeNull();
        result.Count.ShouldBeGreaterThan(0);
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_PasswordHashDoesNotExist_NotFound()
    {
        var result = await _client.CheckPasswordHashAsync("cf7462ba02ed08d001d2e979299e1b3d95ce00e0");

        result.ShouldBeNull();
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_PasswordHashExist_ReturnsSuccess()
    {
        var result = await _client.CheckPasswordHashAsync("81fe8bfe87576c3ecb22426f8e57847382917acf");

        result.ShouldNotBeNull();
        result.Count.ShouldBeGreaterThan(0);
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_WrongLength_ReturnsErrorMessage()
    {
        var act = () => _client.CheckPasswordHashAsync("81fe8bfe87576c3ecb22426f8e5784738");

        var ex = await act.ShouldThrowAsync<HttpRequestException>();
        ex.Message.ShouldBe("Password hash should be 40 hex characters.");
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_NotHexCharacter_ReturnsErrorMessage()
    {
        var act = () => _client.CheckPasswordHashAsync("cf7462ba02ed08d001d2e979299e1b3d95ce00e!");

        var ex = await act.ShouldThrowAsync<HttpRequestException>();
        ex.Message.ShouldBe("Password hash should be 40 hex characters.");
    }
}