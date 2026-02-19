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
using CoderPatros.Jsf.Keys;

namespace CoderPatros.Jsf.Models;

/// <summary>
/// Represents a JSF signature object as it appears in JSON.
/// </summary>
public sealed record SignatureCore
{
    /// <summary>Algorithm identifier (e.g. "ES256").</summary>
    public required string Algorithm { get; init; }

    /// <summary>Embedded public key (optional).</summary>
    public JwkPublicKey? PublicKey { get; init; }

    /// <summary>Key identifier (optional).</summary>
    public string? KeyId { get; init; }

    /// <summary>Certificate path (optional).</summary>
    public IReadOnlyList<string>? CertificatePath { get; init; }

    /// <summary>Properties to exclude from signing (optional).</summary>
    public IReadOnlyList<string>? Excludes { get; init; }

    /// <summary>Extension properties (optional).</summary>
    public IReadOnlyDictionary<string, JsonNode?>? Extensions { get; init; }

    /// <summary>Base64url-encoded signature value.</summary>
    public string? Value { get; init; }
}
