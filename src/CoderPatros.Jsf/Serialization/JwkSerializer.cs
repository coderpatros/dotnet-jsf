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

namespace CoderPatros.Jsf.Serialization;

/// <summary>
/// Serializes/deserializes JWK public keys to/from JSON.
/// </summary>
internal static class JwkSerializer
{
    public static JsonObject Serialize(JwkPublicKey key)
    {
        var obj = new JsonObject { ["kty"] = key.Kty };

        if (key.Crv is not null) obj["crv"] = key.Crv;
        if (key.X is not null) obj["x"] = key.X;
        if (key.Y is not null) obj["y"] = key.Y;
        if (key.N is not null) obj["n"] = key.N;
        if (key.E is not null) obj["e"] = key.E;

        return obj;
    }

    public static JwkPublicKey Deserialize(JsonObject obj)
    {
        return new JwkPublicKey
        {
            Kty = obj["kty"]?.GetValue<string>() ?? throw new JsfException("JWK missing 'kty' property."),
            Crv = obj["crv"]?.GetValue<string>(),
            X = obj["x"]?.GetValue<string>(),
            Y = obj["y"]?.GetValue<string>(),
            N = obj["n"]?.GetValue<string>(),
            E = obj["e"]?.GetValue<string>()
        };
    }
}
