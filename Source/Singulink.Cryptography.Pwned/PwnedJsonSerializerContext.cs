using System.Text.Json;
using System.Text.Json.Serialization;

namespace Singulink.Cryptography.Pwned;

/// <summary>
/// Provides source-generated JSON type info for the types that the service and the client exchange.
/// </summary>
[JsonSerializable(typeof(CheckPasswordResult))]
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
public sealed partial class PwnedJsonSerializerContext : JsonSerializerContext;
