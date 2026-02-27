using CoderPatros.Jsf.Api.Models;
using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Models;

namespace CoderPatros.Jsf.Api.Endpoints;

public static class VerifyEndpoints
{
    public static void MapVerifyEndpoints(this WebApplication app)
    {
        app.MapPost("/api/verify", HandleVerify);
        app.MapPost("/api/signatures/verify", HandleVerifyDirect);
        app.MapPost("/api/signatures/verify-signers", HandleVerifySigners);
        app.MapPost("/api/signatures/verify-chain", HandleVerifyChain);
    }

    private static IResult HandleVerify(VerifyRequest request)
    {
        try
        {
            var service = new JsfSignatureService();
            var options = BuildVerificationOptions(request.Key, request.AllowEmbeddedKey, request.AcceptedAlgorithms);

            using (options.Key)
            {
                var result = service.Verify(request.Document, options);
                return Results.Ok(new VerifyResponse { IsValid = result.IsValid, Error = result.Error });
            }
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }

    private static IResult HandleVerifyDirect(VerifyRequest request)
    {
        return HandleVerify(request);
    }

    private static IResult HandleVerifySigners(VerifySignersRequest request)
    {
        try
        {
            var service = new JsfSignatureService();
            var options = BuildVerificationOptions(request.Key, request.AllowEmbeddedKey, request.AcceptedAlgorithms);

            using (options.Key)
            {
                var result = service.VerifySigners(request.Document, options);
                return Results.Ok(new VerifyResponse { IsValid = result.IsValid, Error = result.Error });
            }
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }

    private static IResult HandleVerifyChain(VerifyChainRequest request)
    {
        try
        {
            var service = new JsfSignatureService();
            var options = BuildVerificationOptions(request.Key, request.AllowEmbeddedKey, request.AcceptedAlgorithms);

            using (options.Key)
            {
                var result = service.VerifyChain(request.Document, options);
                return Results.Ok(new VerifyResponse { IsValid = result.IsValid, Error = result.Error });
            }
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }

    private static VerificationOptions BuildVerificationOptions(
        System.Text.Json.Nodes.JsonObject? keyObj,
        bool allowEmbeddedKey,
        IReadOnlyList<string>? acceptedAlgorithms)
    {
        VerificationKey? verificationKey = null;
        if (keyObj is not null)
        {
            var jwkJson = keyObj.ToJsonString();
            verificationKey = JwkKeyHelper.LoadVerificationKey(jwkJson);
        }

        IReadOnlySet<string>? acceptedAlgorithmsSet = null;
        if (acceptedAlgorithms is { Count: > 0 })
            acceptedAlgorithmsSet = new HashSet<string>(acceptedAlgorithms, StringComparer.Ordinal);

        return new VerificationOptions
        {
            Key = verificationKey,
            AllowEmbeddedPublicKey = allowEmbeddedKey,
            AcceptedAlgorithms = acceptedAlgorithmsSet
        };
    }
}
