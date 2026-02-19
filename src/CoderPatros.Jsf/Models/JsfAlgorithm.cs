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

namespace CoderPatros.Jsf.Models;

/// <summary>
/// JSF/JWA algorithm identifier constants.
/// </summary>
public static class JsfAlgorithm
{
    // ECDSA
    public const string ES256 = "ES256";
    public const string ES384 = "ES384";
    public const string ES512 = "ES512";

    // RSA PKCS#1 v1.5
    public const string RS256 = "RS256";
    public const string RS384 = "RS384";
    public const string RS512 = "RS512";

    // RSA-PSS
    public const string PS256 = "PS256";
    public const string PS384 = "PS384";
    public const string PS512 = "PS512";

    // EdDSA
    public const string Ed25519 = "Ed25519";
    public const string Ed448 = "Ed448";

    // HMAC
    public const string HS256 = "HS256";
    public const string HS384 = "HS384";
    public const string HS512 = "HS512";
}
