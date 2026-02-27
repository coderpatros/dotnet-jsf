using System.Text.Json.Nodes;
using CoderPatros.Jsf.Api.Models;
using CoderPatros.Jsf.Keys;

namespace CoderPatros.Jsf.Api.Endpoints;

public static class KeyEndpoints
{
    private static readonly string[] ValidAlgorithms =
    [
        "ES256", "ES384", "ES512",
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
        "Ed25519", "Ed448",
        "HS256", "HS384", "HS512"
    ];

    public static void MapKeyEndpoints(this WebApplication app)
    {
        app.MapPost("/api/keys/generate", HandleGenerateKey);
    }

    private static IResult HandleGenerateKey(GenerateKeyRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Algorithm))
            return Results.BadRequest(new ErrorResponse { Error = "Algorithm is required." });

        if (!ValidAlgorithms.Contains(request.Algorithm))
            return Results.BadRequest(new ErrorResponse { Error = $"Unsupported algorithm: {request.Algorithm}. Valid algorithms: {string.Join(", ", ValidAlgorithms)}" });

        if (JwkKeyHelper.IsSymmetricAlgorithm(request.Algorithm))
        {
            var symmetricJwk = JwkKeyHelper.GenerateSymmetricKey(request.Algorithm);
            var symmetricKey = JsonNode.Parse(symmetricJwk)!.AsObject();
            return Results.Ok(new GenerateKeyResponse { SymmetricKey = symmetricKey });
        }

        var (privateJwk, publicJwk) = JwkKeyHelper.GenerateAsymmetricKey(request.Algorithm);
        var privateKey = JsonNode.Parse(privateJwk)!.AsObject();
        var publicKey = JsonNode.Parse(publicJwk)!.AsObject();
        return Results.Ok(new GenerateKeyResponse { PrivateKey = privateKey, PublicKey = publicKey });
    }
}
