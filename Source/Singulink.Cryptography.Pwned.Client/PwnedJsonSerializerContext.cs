using System.Text.Json.Serialization;

namespace Singulink.Cryptography.Pwned.Client;

[JsonSerializable(typeof(CheckPasswordResult))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal sealed partial class PwnedJsonSerializerContext : JsonSerializerContext { }
