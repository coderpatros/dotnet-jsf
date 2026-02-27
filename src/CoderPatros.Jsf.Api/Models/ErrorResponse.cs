namespace CoderPatros.Jsf.Api.Models;

public sealed record ErrorResponse
{
    public required string Error { get; init; }
}
