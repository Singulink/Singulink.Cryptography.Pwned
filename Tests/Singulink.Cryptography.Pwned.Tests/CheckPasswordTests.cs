using Shouldly;
using Singulink.Cryptography.Pwned.Client;

namespace Singulink.Cryptography.Pwned.Tests;

[TestClass]
public class CheckPasswordTests
{
    [TestMethod]
    public async Task CheckPasswordAsync_PasswordDoesntExist_NotFound()
    {
        var client = GetClient();
        var result = await client.CheckPasswordAsync("dsjadjbsa");

        result.ShouldBeNull();
    }

    [TestMethod]
    public async Task CheckPasswordAsync_PasswordExists_ReturnsSuccess()
    {
        var client = GetClient();
        var result = await client.CheckPasswordAsync("1234");

        result.ShouldNotBeNull();
        result.Count.ShouldBe(1);
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_PasswordHashDoesntExist_NotFound()
    {
        var client = GetClient();
        var result = await client.CheckPasswordHashAsync("cf7462ba02ed08d001d2e979299e1b3d95ce00e0");

        result.ShouldBeNull();
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_PasswordHashExist_ReturnsSuccess()
    {
        var client = GetClient();
        var result = await client.CheckPasswordHashAsync("81fe8bfe87576c3ecb22426f8e57847382917acf");

        result.ShouldNotBeNull();
        result.Count.ShouldBe(2);
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_WrongLength_ReturnsErrorMessage()
    {
        var client = GetClient();

        var act = () => client.CheckPasswordHashAsync("81fe8bfe87576c3ecb22426f8e5784738");

        var ex = await act.ShouldThrowAsync<HttpRequestException>();
        ex.Message.ShouldBe("Password hash should be 40 hex characters.");
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_NotHexCharacter_ReturnsErrorMessage()
    {
        var client = GetClient();

        var act = () => client.CheckPasswordHashAsync("cf7462ba02ed08d001d2e979299e1b3d95ce00e!");

        var ex = await act.ShouldThrowAsync<HttpRequestException>();
        ex.Message.ShouldBe("Password hash should be 40 hex characters.");
    }

    private static PwnedClient GetClient()
    {
        var httpClientFactory = new PwnedClientHttpFactory();
        var client = new PwnedClient(httpClientFactory);
        PwnedClient.ApiBaseUri = httpClientFactory.CreateClient().BaseAddress ?? throw new InvalidOperationException("Base address not found.");
        return client;
    }
}