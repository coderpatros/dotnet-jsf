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
using CoderPatros.Jsf.Models;

namespace CoderPatros.Jsf.Serialization;

/// <summary>
/// Serializes/deserializes SignatureCore to/from JsonObject.
/// </summary>
internal static class SignatureCoreSerializer
{
    public static JsonObject Serialize(SignatureCore sig)
    {
        var obj = new JsonObject { ["algorithm"] = sig.Algorithm };

        if (sig.PublicKey is not null)
            obj["publicKey"] = JwkSerializer.Serialize(sig.PublicKey);

        if (sig.KeyId is not null)
            obj["keyId"] = sig.KeyId;

        if (sig.CertificatePath is not null)
        {
            var arr = new JsonArray();
            foreach (var cert in sig.CertificatePath)
                arr.Add(JsonValue.Create(cert));
            obj["certificatePath"] = arr;
        }

        if (sig.Excludes is not null)
        {
            var arr = new JsonArray();
            foreach (var ex in sig.Excludes)
                arr.Add(JsonValue.Create(ex));
            obj["excludes"] = arr;
        }

        if (sig.Extensions is not null && sig.Extensions.Count > 0)
        {
            var extNames = new JsonArray();
            foreach (var key in sig.Extensions.Keys)
                extNames.Add(JsonValue.Create(key));
            obj["extensions"] = extNames;
            foreach (var (key, value) in sig.Extensions)
                obj[key] = value?.DeepClone();
        }

        if (sig.Value is not null)
            obj["value"] = sig.Value;

        return obj;
    }

    public static SignatureCore Deserialize(JsonObject obj)
    {
        var algorithm = obj["algorithm"]?.GetValue<string>()
            ?? throw new JsfException("Signature object missing 'algorithm' property.");

        Keys.JwkPublicKey? publicKey = null;
        if (obj["publicKey"] is JsonObject pkObj)
            publicKey = JwkSerializer.Deserialize(pkObj);

        var keyId = obj["keyId"]?.GetValue<string>();

        List<string>? certificatePath = null;
        if (obj["certificatePath"] is JsonArray certArr)
            certificatePath = certArr.Select(n => n!.GetValue<string>()).ToList();

        List<string>? excludes = null;
        if (obj["excludes"] is JsonArray exArr)
            excludes = exArr.Select(n => n!.GetValue<string>()).ToList();

        var value = obj["value"]?.GetValue<string>();

        // Extensions: if "extensions" declaration array exists, use it to identify extension properties.
        // Otherwise fall back to treating unknown properties as extensions (backward compat).
        Dictionary<string, JsonNode?>? extensions = null;
        var knownProps = new HashSet<string>(StringComparer.Ordinal)
        {
            "algorithm", "publicKey", "keyId", "certificatePath", "excludes", "value", "extensions"
        };

        if (obj["extensions"] is JsonArray extDeclArr)
        {
            foreach (var extNameNode in extDeclArr)
            {
                var extName = extNameNode!.GetValue<string>();
                extensions ??= new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
                extensions[extName] = obj[extName]?.DeepClone();
            }
        }
        else
        {
            foreach (var prop in obj)
            {
                if (!knownProps.Contains(prop.Key))
                {
                    extensions ??= new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
                    extensions[prop.Key] = prop.Value?.DeepClone();
                }
            }
        }

        return new SignatureCore
        {
            Algorithm = algorithm,
            PublicKey = publicKey,
            KeyId = keyId,
            CertificatePath = certificatePath,
            Excludes = excludes,
            Extensions = extensions,
            Value = value
        };
    }
}
