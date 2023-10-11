using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;
using Singulink.Cryptography.Pwned.Client;

namespace Singulink.Cryptography.Pwned.Tests;

[TestClass]
public class CheckPasswordTests
{
    [TestMethod]
    public async Task CheckPasswordAsync_PasswordDoesntExist_NotFound()
    {
        var httpClientFactory = new PwnedClientHttpFactory();
        var client = new PwnedClient(httpClientFactory);
        PwnedClient.ApiBaseUri = httpClientFactory.CreateClient().BaseAddress;

        var result = await client.CheckPasswordAsync("dsjadjbsa");

        result.ShouldBeNull();
    }

    [TestMethod]
    public async Task CheckPasswordAsync_PasswordExists_ReturnsSuccess()
    {
        var httpClientFactory = new PwnedClientHttpFactory();
        var client = new PwnedClient(httpClientFactory);
        PwnedClient.ApiBaseUri = httpClientFactory.CreateClient().BaseAddress;

        var result = await client.CheckPasswordAsync("1234");

        result.ShouldNotBeNull();
        result.Count.ShouldBe(1);
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_PasswordHashDoesntExist_NotFound()
    {
        var httpClientFactory = new PwnedClientHttpFactory();
        var client = new PwnedClient(httpClientFactory);
        PwnedClient.ApiBaseUri = httpClientFactory.CreateClient().BaseAddress;

        var result = await client.CheckPasswordHashAsync("cf7462ba02ed08d001d2e979299e1b3d95ce00e0");

        result.ShouldBeNull();
    }

    [TestMethod]
    public async Task CheckPasswordHashAsync_PasswordHashExist_ReturnsSuccess()
    {
        var httpClientFactory = new PwnedClientHttpFactory();
        var client = new PwnedClient(httpClientFactory);
        PwnedClient.ApiBaseUri = httpClientFactory.CreateClient().BaseAddress;

        var result = await client.CheckPasswordHashAsync("81fe8bfe87576c3ecb22426f8e57847382917acf");

        result.ShouldNotBeNull();
        result.Count.ShouldBe(2);
    }
}