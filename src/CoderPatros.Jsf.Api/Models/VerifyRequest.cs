using System.Text.Json.Nodes;

namespace CoderPatros.Jsf.Api.Models;

public sealed record VerifyRequest
{
    public required JsonObject Document { get; init; }
    public JsonObject? Key { get; init; }
    public bool AllowEmbeddedKey { get; init; }
    public IReadOnlyList<string>? AcceptedAlgorithms { get; init; }
}
