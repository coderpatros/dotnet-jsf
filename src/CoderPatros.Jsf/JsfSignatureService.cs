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
using CoderPatros.Jsf.Operations;

namespace CoderPatros.Jsf;

/// <summary>
/// Public facade for JSF signing and verification operations.
/// </summary>
public sealed class JsfSignatureService
{
    private readonly JsfSigner _signer;
    private readonly JsfVerifier _verifier;

    public JsfSignatureService()
        : this(new SignatureAlgorithmRegistry())
    {
    }

    public JsfSignatureService(SignatureAlgorithmRegistry registry)
    {
        _signer = new JsfSigner(registry);
        _verifier = new JsfVerifier(registry);
    }

    /// <summary>
    /// Signs a JSON document with a single signature.
    /// Returns a new document with the "signature" property added.
    /// </summary>
    public JsonObject Sign(JsonObject document, SignatureOptions options)
    {
        return _signer.Sign(document, options);
    }

    /// <summary>
    /// Signs a JSON string with a single signature.
    /// Returns the signed JSON string.
    /// </summary>
    public string Sign(string json, SignatureOptions options)
    {
        var doc = JsonNode.Parse(json)?.AsObject()
            ?? throw new JsfException("Input is not a valid JSON object.");
        var signed = _signer.Sign(doc, options);
        return signed.ToJsonString();
    }

    /// <summary>
    /// Adds a signer to a multi-signature document.
    /// Returns a new document with the signer added to the "signers" array.
    /// </summary>
    public JsonObject AddSigner(JsonObject document, SignatureOptions options)
    {
        return _signer.AddSigner(document, options);
    }

    /// <summary>
    /// Appends a signature to a signature chain.
    /// Returns a new document with the entry added to the "signatureChain" array.
    /// </summary>
    public JsonObject AppendToChain(JsonObject document, SignatureOptions options)
    {
        return _signer.AppendToChain(document, options);
    }

    /// <summary>
    /// Verifies a single-signature document.
    /// </summary>
    public VerificationResult Verify(JsonObject document, VerificationOptions options)
    {
        return _verifier.Verify(document, options);
    }

    /// <summary>
    /// Verifies a single-signature document from JSON string.
    /// </summary>
    public VerificationResult Verify(string json, VerificationOptions options)
    {
        var doc = JsonNode.Parse(json)?.AsObject()
            ?? throw new JsfException("Input is not a valid JSON object.");
        return _verifier.Verify(doc, options);
    }

    /// <summary>
    /// Verifies all signatures in a multi-signer document.
    /// </summary>
    public VerificationResult VerifySigners(JsonObject document, VerificationOptions options)
    {
        return _verifier.VerifySigners(document, options);
    }

    /// <summary>
    /// Verifies all entries in a signature chain.
    /// </summary>
    public VerificationResult VerifyChain(JsonObject document, VerificationOptions options)
    {
        return _verifier.VerifyChain(document, options);
    }
}
