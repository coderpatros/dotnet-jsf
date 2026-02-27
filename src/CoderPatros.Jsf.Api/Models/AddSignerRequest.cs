using System.Text.Json.Nodes;

namespace CoderPatros.Jsf.Api.Models;

public sealed record AddSignerRequest
{
    public required JsonObject Document { get; init; }
    public required string Algorithm { get; init; }
    public required JsonObject Key { get; init; }
    public bool EmbedPublicKey { get; init; }
    public string? KeyId { get; init; }
}
