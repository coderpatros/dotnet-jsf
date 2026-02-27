namespace CoderPatros.Jsf.Api.Models;

public sealed record VerifyResponse
{
    public required bool IsValid { get; init; }
    public string? Error { get; init; }
}
