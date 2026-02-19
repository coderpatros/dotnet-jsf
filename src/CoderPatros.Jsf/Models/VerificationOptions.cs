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

using CoderPatros.Jsf.Keys;

namespace CoderPatros.Jsf.Models;

/// <summary>
/// Configuration for a verification operation.
/// </summary>
public sealed record VerificationOptions
{
    /// <summary>Key for verification.</summary>
    public VerificationKey? Key { get; init; }

    /// <summary>
    /// Key resolver for multi-signature/chain verification.
    /// Called with each signature to resolve the appropriate verification key.
    /// </summary>
    public Func<SignatureCore, VerificationKey>? KeyResolver { get; init; }

    /// <summary>
    /// When true, allows verification using the public key embedded in the signature.
    /// Defaults to false. Only enable this when you trust the source of the document,
    /// as an attacker can embed any public key in a signature they create.
    /// </summary>
    public bool AllowEmbeddedPublicKey { get; init; }

    /// <summary>Custom signature property name (default: "signature").</summary>
    public string SignaturePropertyName { get; init; } = "signature";
}
