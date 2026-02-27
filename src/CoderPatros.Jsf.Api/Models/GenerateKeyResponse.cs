using System.Text.Json.Nodes;

namespace CoderPatros.Jsf.Api.Models;

public sealed record GenerateKeyResponse
{
    public JsonObject? PrivateKey { get; init; }
    public JsonObject? PublicKey { get; init; }
    public JsonObject? SymmetricKey { get; init; }
}
