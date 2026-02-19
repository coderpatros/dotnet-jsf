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
using CoderPatros.Jsf.Canonicalization;
using CoderPatros.Jsf.Models;
using CoderPatros.Jsf.Serialization;

namespace CoderPatros.Jsf.Operations;

/// <summary>
/// JSON-level operations on signature objects within documents.
/// </summary>
internal static class SignatureObjectManipulator
{
    /// <summary>
    /// Inserts a signature property into a document clone and returns the clone.
    /// </summary>
    public static JsonObject InsertSignature(JsonObject document, JsonObject signatureObj, string signaturePropertyName = "signature")
    {
        var clone = document.DeepClone().AsObject();
        clone[signaturePropertyName] = signatureObj;
        return clone;
    }

    /// <summary>
    /// Creates canonicalized bytes for signing: removes "value" from signature object,
    /// optionally removes excluded properties, then canonicalizes.
    /// </summary>
    public static byte[] CreateSigningInput(JsonObject document, SignatureCore sigMetadata, string signaturePropertyName = "signature")
    {
        var clone = document.DeepClone().AsObject();

        // Remove excluded top-level properties
        if (sigMetadata.Excludes is not null)
        {
            foreach (var prop in sigMetadata.Excludes)
                clone.Remove(prop);
        }

        // Build the signature object without "value"
        var sigObj = SignatureCoreSerializer.Serialize(sigMetadata with { Value = null });
        clone[signaturePropertyName] = sigObj;

        var canonical = JsonCanonicalizer.Canonicalize(clone);
        return System.Text.Encoding.UTF8.GetBytes(canonical);
    }

    /// <summary>
    /// Creates canonicalized bytes for verifying a single signature within a signers array.
    /// </summary>
    public static byte[] CreateMultiSignerSigningInput(JsonObject document, SignatureCore sigMetadata, int signerIndex)
    {
        var clone = document.DeepClone().AsObject();

        if (sigMetadata.Excludes is not null)
        {
            foreach (var prop in sigMetadata.Excludes)
                clone.Remove(prop);
        }

        // For multi-signature, each signer signs the document with only their own
        // signature object (without value) in the signers array
        var sigObj = SignatureCoreSerializer.Serialize(sigMetadata with { Value = null });

        // Build a signers array with only this signature at its position
        var signersArray = new JsonArray { sigObj };
        clone["signers"] = signersArray;

        var canonical = JsonCanonicalizer.Canonicalize(clone);
        return System.Text.Encoding.UTF8.GetBytes(canonical);
    }

    /// <summary>
    /// Creates canonicalized bytes for verifying a signature chain entry.
    /// The chain entry is treated like a single signature.
    /// </summary>
    public static byte[] CreateChainSigningInput(JsonObject document, SignatureCore sigMetadata, string signaturePropertyName = "signature")
    {
        var clone = document.DeepClone().AsObject();

        if (sigMetadata.Excludes is not null)
        {
            foreach (var prop in sigMetadata.Excludes)
                clone.Remove(prop);
        }

        // The chain entry replaces the signatureChain array with just this entry (without value)
        var sigObj = SignatureCoreSerializer.Serialize(sigMetadata with { Value = null });
        clone[signaturePropertyName] = sigObj;

        var canonical = JsonCanonicalizer.Canonicalize(clone);
        return System.Text.Encoding.UTF8.GetBytes(canonical);
    }

    /// <summary>
    /// Extracts a SignatureCore from a document's "signature" property.
    /// </summary>
    public static SignatureCore ExtractSignature(JsonObject document, string signaturePropertyName = "signature")
    {
        var sigNode = document[signaturePropertyName] as JsonObject
            ?? throw new JsfException($"Document does not contain a '{signaturePropertyName}' property.");
        return SignatureCoreSerializer.Deserialize(sigNode);
    }

    /// <summary>
    /// Extracts all SignatureCore objects from a document's "signers" array.
    /// </summary>
    public static IReadOnlyList<SignatureCore> ExtractSigners(JsonObject document)
    {
        var signersNode = document["signers"] as JsonArray
            ?? throw new JsfException("Document does not contain a 'signers' property.");

        return signersNode
            .Select(n => SignatureCoreSerializer.Deserialize(n!.AsObject()))
            .ToList();
    }

    /// <summary>
    /// Extracts all SignatureCore objects from a document's "signatureChain" array.
    /// </summary>
    public static IReadOnlyList<SignatureCore> ExtractChain(JsonObject document)
    {
        var chainNode = document["signatureChain"] as JsonArray
            ?? throw new JsfException("Document does not contain a 'signatureChain' property.");

        return chainNode
            .Select(n => SignatureCoreSerializer.Deserialize(n!.AsObject()))
            .ToList();
    }
}
