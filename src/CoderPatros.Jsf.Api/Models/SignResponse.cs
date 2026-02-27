using System.Text.Json.Nodes;

namespace CoderPatros.Jsf.Api.Models;

public sealed record SignResponse
{
    public required JsonObject Document { get; init; }
}
