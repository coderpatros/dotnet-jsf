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
using CoderPatros.Jsf.Models;
using CoderPatros.Jsf.Serialization;

namespace CoderPatros.Jsf.Operations;

/// <summary>
/// Orchestrates JSF signing operations.
/// </summary>
internal sealed class JsfSigner
{
    private readonly SignatureAlgorithmRegistry _registry;

    public JsfSigner(SignatureAlgorithmRegistry registry)
    {
        _registry = registry;
    }

    /// <summary>
    /// Signs a document with a single signature. Never mutates the input.
    /// </summary>
    public JsonObject Sign(JsonObject document, SignatureOptions options)
    {
        var algorithm = _registry.Get(options.Algorithm);
        var clone = document.DeepClone().AsObject();

        var sigMetadata = new SignatureCore
        {
            Algorithm = options.Algorithm,
            PublicKey = options.PublicKey,
            KeyId = options.KeyId,
            CertificatePath = options.CertificatePath,
            Excludes = options.Excludes,
            Extensions = options.Extensions
        };

        var signingInput = SignatureObjectManipulator.CreateSigningInput(clone, sigMetadata, options.SignaturePropertyName);
        var signatureBytes = algorithm.Sign(signingInput, options.Key);
        var signatureValue = Base64UrlEncoding.Encode(signatureBytes);

        var finalSig = sigMetadata with { Value = signatureValue };
        var sigObj = SignatureCoreSerializer.Serialize(finalSig);

        clone[options.SignaturePropertyName] = sigObj;
        return clone;
    }

    /// <summary>
    /// Adds a signer to the document's "signers" array.
    /// </summary>
    public JsonObject AddSigner(JsonObject document, SignatureOptions options)
    {
        var algorithm = _registry.Get(options.Algorithm);
        var clone = document.DeepClone().AsObject();

        var sigMetadata = new SignatureCore
        {
            Algorithm = options.Algorithm,
            PublicKey = options.PublicKey,
            KeyId = options.KeyId,
            CertificatePath = options.CertificatePath,
            Excludes = options.Excludes,
            Extensions = options.Extensions
        };

        // Build signing input: document with this signer's signature (without value) as the only signer
        var signingInput = SignatureObjectManipulator.CreateMultiSignerSigningInput(clone, sigMetadata, 0);
        var signatureBytes = algorithm.Sign(signingInput, options.Key);
        var signatureValue = Base64UrlEncoding.Encode(signatureBytes);

        var finalSig = sigMetadata with { Value = signatureValue };
        var sigObj = SignatureCoreSerializer.Serialize(finalSig);

        // Add to existing signers array or create one
        if (clone["signers"] is JsonArray existing)
        {
            existing.Add(sigObj);
        }
        else
        {
            clone["signers"] = new JsonArray(sigObj);
        }

        return clone;
    }

    /// <summary>
    /// Appends a signature to the document's "signatureChain" array.
    /// </summary>
    public JsonObject AppendToChain(JsonObject document, SignatureOptions options)
    {
        var algorithm = _registry.Get(options.Algorithm);
        var clone = document.DeepClone().AsObject();

        var sigMetadata = new SignatureCore
        {
            Algorithm = options.Algorithm,
            PublicKey = options.PublicKey,
            KeyId = options.KeyId,
            CertificatePath = options.CertificatePath,
            Excludes = options.Excludes,
            Extensions = options.Extensions
        };

        // For chain, each entry signs the document as-is (including previous chain entries)
        // with its own signature replacing the signatureChain
        var signingInput = SignatureObjectManipulator.CreateChainSigningInput(clone, sigMetadata);
        var signatureBytes = algorithm.Sign(signingInput, options.Key);
        var signatureValue = Base64UrlEncoding.Encode(signatureBytes);

        var finalSig = sigMetadata with { Value = signatureValue };
        var sigObj = SignatureCoreSerializer.Serialize(finalSig);

        if (clone["signatureChain"] is JsonArray existing)
        {
            existing.Add(sigObj);
        }
        else
        {
            clone["signatureChain"] = new JsonArray(sigObj);
        }

        return clone;
    }
}
