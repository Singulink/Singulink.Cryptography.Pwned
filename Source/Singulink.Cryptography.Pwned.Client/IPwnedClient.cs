namespace Singulink.Cryptography.Pwned.Client;

public interface IPwnedClient
{
    Task<CheckPasswordResult?> CheckPasswordAsync(string password);

    Task<CheckPasswordResult?> CheckPasswordHashAsync(string passwordHash);
}