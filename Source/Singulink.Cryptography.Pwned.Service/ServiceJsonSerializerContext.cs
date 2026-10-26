using System.Text.Json;
using System.Text.Json.Serialization;

namespace Singulink.Cryptography.Pwned.Service;

/// <summary>
/// Provides source-generated JSON type info for the service's own response types. The types shared with the client are in <see
/// cref="PwnedJsonSerializerContext"/>.
/// </summary>
[JsonSerializable(typeof(ServiceStatus))]
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
internal sealed partial class ServiceJsonSerializerContext : JsonSerializerContext;
