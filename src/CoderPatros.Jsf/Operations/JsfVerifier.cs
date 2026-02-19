// This file is part of CoderPatros.JSF Library for .NET
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Text.Json.Nodes;
using CoderPatros.Jsf.Crypto;
using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Models;
using CoderPatros.Jsf.Serialization;

namespace CoderPatros.Jsf.Operations;

/// <summary>
/// Orchestrates JSF verification operations.
/// </summary>
internal sealed class JsfVerifier
{
    private readonly SignatureAlgorithmRegistry _registry;

    public JsfVerifier(SignatureAlgorithmRegistry registry)
    {
        _registry = registry;
    }

    /// <summary>
    /// Verifies a single signature on a document.
    /// </summary>
    public VerificationResult Verify(JsonObject document, VerificationOptions options)
    {
        try
        {
            var sig = SignatureObjectManipulator.ExtractSignature(document, options.SignaturePropertyName);
            var algorithmCheck = CheckAcceptedAlgorithm(sig.Algorithm, options);
            if (algorithmCheck is not null)
                return algorithmCheck;
            var key = ResolveKey(sig, options);
            return VerifySingleSignature(document, sig, key, options.SignaturePropertyName);
        }
        catch (Exception ex) when (ex is not JsfException)
        {
            return VerificationResult.Failure($"Verification error: {ex.Message}");
        }
    }

    /// <summary>
    /// Verifies all signatures in a multi-signer document.
    /// </summary>
    public VerificationResult VerifySigners(JsonObject document, VerificationOptions options)
    {
        try
        {
            var signers = SignatureObjectManipulator.ExtractSigners(document);

            for (int i = 0; i < signers.Count; i++)
            {
                var sig = signers[i];
                var algorithmCheck = CheckAcceptedAlgorithm(sig.Algorithm, options);
                if (algorithmCheck is not null)
                    return algorithmCheck;
                var key = ResolveKey(sig, options);
                var result = VerifyMultiSignerSignature(document, sig, key, i);
                if (!result.IsValid)
                    return VerificationResult.Failure($"Signer {i} verification failed: {result.Error}");
            }

            return VerificationResult.Success();
        }
        catch (Exception ex) when (ex is not JsfException)
        {
            return VerificationResult.Failure($"Verification error: {ex.Message}");
        }
    }

    /// <summary>
    /// Verifies all entries in a signature chain.
    /// </summary>
    public VerificationResult VerifyChain(JsonObject document, VerificationOptions options)
    {
        try
        {
            var chain = SignatureObjectManipulator.ExtractChain(document);

            for (int i = 0; i < chain.Count; i++)
            {
                var sig = chain[i];
                var algorithmCheck = CheckAcceptedAlgorithm(sig.Algorithm, options);
                if (algorithmCheck is not null)
                    return algorithmCheck;
                var key = ResolveKey(sig, options);

                // Build the document as it was when this chain entry was created
                var docAtEntry = BuildDocumentAtChainEntry(document, chain, i);
                var result = VerifyChainEntry(docAtEntry, sig, key);
                if (!result.IsValid)
                    return VerificationResult.Failure($"Chain entry {i} verification failed: {result.Error}");
            }

            return VerificationResult.Success();
        }
        catch (Exception ex) when (ex is not JsfException)
        {
            return VerificationResult.Failure($"Verification error: {ex.Message}");
        }
    }

    private VerificationResult VerifySingleSignature(JsonObject document, SignatureCore sig, VerificationKey key, string signaturePropertyName = "signature")
    {
        if (sig.Value is null)
            return VerificationResult.Failure("Signature has no value.");

        var algorithm = _registry.Get(sig.Algorithm);
        var clone = document.DeepClone().AsObject();

        var signingInput = SignatureObjectManipulator.CreateSigningInput(clone, sig, signaturePropertyName);
        var signatureBytes = Base64UrlEncoding.Decode(sig.Value);

        var verificationKey = ResolveVerificationKey(key);
        var isValid = algorithm.Verify(signingInput, signatureBytes, verificationKey);

        return isValid ? VerificationResult.Success() : VerificationResult.Failure("Signature is invalid.");
    }

    private VerificationResult VerifyMultiSignerSignature(JsonObject document, SignatureCore sig, VerificationKey key, int index)
    {
        if (sig.Value is null)
            return VerificationResult.Failure("Signature has no value.");

        var algorithm = _registry.Get(sig.Algorithm);
        var clone = document.DeepClone().AsObject();

        // Remove the signers array before creating signing input
        clone.Remove("signers");

        var signingInput = SignatureObjectManipulator.CreateMultiSignerSigningInput(clone, sig, index);
        var signatureBytes = Base64UrlEncoding.Decode(sig.Value);

        var verificationKey = ResolveVerificationKey(key);
        var isValid = algorithm.Verify(signingInput, signatureBytes, verificationKey);

        return isValid ? VerificationResult.Success() : VerificationResult.Failure("Signature is invalid.");
    }

    private VerificationResult VerifyChainEntry(JsonObject document, SignatureCore sig, VerificationKey key)
    {
        if (sig.Value is null)
            return VerificationResult.Failure("Signature has no value.");

        var algorithm = _registry.Get(sig.Algorithm);

        var signingInput = SignatureObjectManipulator.CreateChainSigningInput(document, sig);
        var signatureBytes = Base64UrlEncoding.Decode(sig.Value);

        var verificationKey = ResolveVerificationKey(key);
        var isValid = algorithm.Verify(signingInput, signatureBytes, verificationKey);

        return isValid ? VerificationResult.Success() : VerificationResult.Failure("Signature is invalid.");
    }

    private static JsonObject BuildDocumentAtChainEntry(JsonObject document, IReadOnlyList<SignatureCore> chain, int index)
    {
        var clone = document.DeepClone().AsObject();

        // Remove the signatureChain - the chain entry signing treats the document
        // with the previous chain entries already present
        clone.Remove("signatureChain");

        // Add previous chain entries
        if (index > 0)
        {
            var prevChain = new JsonArray();
            for (int i = 0; i < index; i++)
                prevChain.Add(SignatureCoreSerializer.Serialize(chain[i]));
            clone["signatureChain"] = prevChain;
        }

        return clone;
    }

    private static VerificationResult? CheckAcceptedAlgorithm(string algorithm, VerificationOptions options)
    {
        if (options.AcceptedAlgorithms is not null && !options.AcceptedAlgorithms.Contains(algorithm))
            return VerificationResult.Failure($"Algorithm '{algorithm}' is not in the accepted algorithms list.");
        return null;
    }

    private static VerificationKey ResolveKey(SignatureCore sig, VerificationOptions options)
    {
        if (options.KeyResolver is not null)
            return options.KeyResolver(sig);

        if (options.Key is not null)
            return options.Key;

        if (options.AllowEmbeddedPublicKey && sig.PublicKey is not null)
            return JwkKeyConverter.ToVerificationKey(sig.PublicKey);

        throw new JsfException("No verification key available. Provide a key or key resolver. To use the embedded public key, set AllowEmbeddedPublicKey to true.");
    }

    private static VerificationKey ResolveVerificationKey(VerificationKey key)
    {
        // If the key wraps a JwkPublicKey, convert it to a concrete key
        if (key.KeyMaterial is JwkPublicKey jwk)
            return JwkKeyConverter.ToVerificationKey(jwk);
        return key;
    }
}
