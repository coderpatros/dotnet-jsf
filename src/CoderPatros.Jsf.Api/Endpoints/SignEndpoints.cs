using System.Text.Json.Nodes;
using CoderPatros.Jsf.Api.Models;
using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Models;

namespace CoderPatros.Jsf.Api.Endpoints;

public static class SignEndpoints
{
    public static void MapSignEndpoints(this WebApplication app)
    {
        app.MapPost("/api/sign", HandleSign);
        app.MapPost("/api/signatures/sign", HandleSignDirect);
        app.MapPost("/api/signatures/add-signer", HandleAddSigner);
        app.MapPost("/api/signatures/append-to-chain", HandleAppendToChain);
    }

    private static IResult HandleSign(SignRequest request)
    {
        try
        {
            var service = new JsfSignatureService();
            var jwkJson = request.Key.ToJsonString();
            using var signingKey = JwkKeyHelper.LoadSigningKey(jwkJson);

            var options = new SignatureOptions
            {
                Algorithm = request.Algorithm,
                Key = signingKey,
                KeyId = request.KeyId
            };

            if (request.EmbedPublicKey)
            {
                var publicKey = JwkKeyHelper.ExtractPublicKey(jwkJson);
                if (publicKey is null)
                    return Results.BadRequest(new ErrorResponse { Error = "Cannot embed public key for symmetric (HMAC) keys." });
                options = options with { PublicKey = publicKey };
            }

            var signed = service.Sign(request.Document, options);
            return Results.Ok(new SignResponse { Document = signed });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }

    private static IResult HandleSignDirect(SignRequest request)
    {
        return HandleSign(request);
    }

    private static IResult HandleAddSigner(AddSignerRequest request)
    {
        try
        {
            var service = new JsfSignatureService();
            var jwkJson = request.Key.ToJsonString();
            using var signingKey = JwkKeyHelper.LoadSigningKey(jwkJson);

            var options = new SignatureOptions
            {
                Algorithm = request.Algorithm,
                Key = signingKey,
                KeyId = request.KeyId
            };

            if (request.EmbedPublicKey)
            {
                var publicKey = JwkKeyHelper.ExtractPublicKey(jwkJson);
                if (publicKey is null)
                    return Results.BadRequest(new ErrorResponse { Error = "Cannot embed public key for symmetric (HMAC) keys." });
                options = options with { PublicKey = publicKey };
            }

            var result = service.AddSigner(request.Document, options);
            return Results.Ok(new SignResponse { Document = result });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }

    private static IResult HandleAppendToChain(AppendToChainRequest request)
    {
        try
        {
            var service = new JsfSignatureService();
            var jwkJson = request.Key.ToJsonString();
            using var signingKey = JwkKeyHelper.LoadSigningKey(jwkJson);

            var options = new SignatureOptions
            {
                Algorithm = request.Algorithm,
                Key = signingKey,
                KeyId = request.KeyId
            };

            if (request.EmbedPublicKey)
            {
                var publicKey = JwkKeyHelper.ExtractPublicKey(jwkJson);
                if (publicKey is null)
                    return Results.BadRequest(new ErrorResponse { Error = "Cannot embed public key for symmetric (HMAC) keys." });
                options = options with { PublicKey = publicKey };
            }

            var result = service.AppendToChain(request.Document, options);
            return Results.Ok(new SignResponse { Document = result });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }
}
