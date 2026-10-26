using System.Globalization;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.OpenApi;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Singulink.Cryptography.Pwned.Service;

/// <summary>
/// Gives the responses of the OpenAPI document the descriptions of the endpoints' response metadata (see <see cref="ErrorResponseMetadata"/>), which
/// Swashbuckle doesn't use itself.
/// </summary>
internal sealed class ResponseDescriptionFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        if (operation.Responses is null)
            return;

        foreach (var metadata in context.ApiDescription.ActionDescriptor.EndpointMetadata.OfType<IProducesResponseTypeMetadata>())
        {
            string statusCode = metadata.StatusCode.ToString(CultureInfo.InvariantCulture);

            if (metadata.Description is { Length: > 0 } description && operation.Responses.TryGetValue(statusCode, out var response))
                response.Description = description;
        }
    }
}
