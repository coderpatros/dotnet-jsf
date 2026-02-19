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

using System.CommandLine;
using System.Text.Json.Nodes;
using CoderPatros.Jsf;
using CoderPatros.Jsf.Cli;
using CoderPatros.Jsf.Models;

var validAlgorithms = new[]
{
    "ES256", "ES384", "ES512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "Ed25519", "Ed448",
    "HS256", "HS384", "HS512"
};

// --- generate-key command ---

var genAlgorithmOption = new Option<string>("--algorithm", "-a")
{
    Description = "Algorithm identifier: " + string.Join(", ", validAlgorithms),
    Required = true
};

var genOutputOption = new Option<DirectoryInfo?>("--output", "-o")
{
    Description = "Output directory for key files (defaults to current directory)"
};

var generateKeyCommand = new Command("generate-key", "Generate a cryptographic key pair (or symmetric key for HMAC)");
generateKeyCommand.Options.Add(genAlgorithmOption);
generateKeyCommand.Options.Add(genOutputOption);

generateKeyCommand.SetAction(parseResult =>
{
    var algorithm = parseResult.GetValue(genAlgorithmOption)!;
    var outputDir = parseResult.GetValue(genOutputOption)
        ?? new DirectoryInfo(Directory.GetCurrentDirectory());

    if (!validAlgorithms.Contains(algorithm))
    {
        Console.Error.WriteLine($"Unsupported algorithm: {algorithm}");
        Console.Error.WriteLine($"Valid algorithms: {string.Join(", ", validAlgorithms)}");
        return 1;
    }

    if (!outputDir.Exists)
        outputDir.Create();

    if (JwkKeyHelper.IsSymmetricAlgorithm(algorithm))
    {
        var symmetricJwk = JwkKeyHelper.GenerateSymmetricKey(algorithm);
        var symmetricPath = Path.Combine(outputDir.FullName, $"{algorithm}-symmetric.jwk");
        File.WriteAllText(symmetricPath, symmetricJwk);
        Console.WriteLine($"Symmetric key written to {symmetricPath}");
    }
    else
    {
        var (privateJwk, publicJwk) = JwkKeyHelper.GenerateAsymmetricKey(algorithm);
        var privatePath = Path.Combine(outputDir.FullName, $"{algorithm}-private.jwk");
        var publicPath = Path.Combine(outputDir.FullName, $"{algorithm}-public.jwk");
        File.WriteAllText(privatePath, privateJwk);
        File.WriteAllText(publicPath, publicJwk);
        Console.WriteLine($"Private key written to {privatePath}");
        Console.WriteLine($"Public key written to {publicPath}");
    }

    return 0;
});

// --- sign command ---

var signKeyOption = new Option<FileInfo>("--key", "-k")
{
    Description = "Path to private/symmetric JWK file",
    Required = true
};

var signAlgorithmOption = new Option<string>("--algorithm", "-a")
{
    Description = "Algorithm identifier",
    Required = true
};

var embedPublicKeyOption = new Option<bool>("--embed-public-key")
{
    Description = "Embed public key in signature"
};

var keyIdOption = new Option<string?>("--key-id")
{
    Description = "Key identifier string"
};

var signInputOption = new Option<FileInfo?>("--input", "-i")
{
    Description = "Path to JSON file (defaults to stdin)"
};

var signCommand = new Command("sign", "Sign a JSON document");
signCommand.Options.Add(signKeyOption);
signCommand.Options.Add(signAlgorithmOption);
signCommand.Options.Add(embedPublicKeyOption);
signCommand.Options.Add(keyIdOption);
signCommand.Options.Add(signInputOption);

signCommand.SetAction(parseResult =>
{
    var keyFile = parseResult.GetValue(signKeyOption)!;
    var algorithm = parseResult.GetValue(signAlgorithmOption)!;
    var embedPublicKey = parseResult.GetValue(embedPublicKeyOption);
    var keyId = parseResult.GetValue(keyIdOption);
    var inputFile = parseResult.GetValue(signInputOption);

    if (!validAlgorithms.Contains(algorithm))
    {
        Console.Error.WriteLine($"Unsupported algorithm: {algorithm}");
        return 1;
    }

    if (!keyFile.Exists)
    {
        Console.Error.WriteLine($"Key file not found: {keyFile.FullName}");
        return 1;
    }

    var jwkJson = File.ReadAllText(keyFile.FullName);
    var signingKey = JwkKeyHelper.LoadSigningKey(jwkJson);

    string jsonInput;
    if (inputFile is not null)
    {
        if (!inputFile.Exists)
        {
            Console.Error.WriteLine($"Input file not found: {inputFile.FullName}");
            return 1;
        }
        jsonInput = File.ReadAllText(inputFile.FullName);
    }
    else
    {
        jsonInput = Console.In.ReadToEnd();
    }

    var options = new SignatureOptions
    {
        Algorithm = algorithm,
        Key = signingKey,
        KeyId = keyId
    };

    if (embedPublicKey)
    {
        var publicKey = JwkKeyHelper.ExtractPublicKey(jwkJson);
        if (publicKey is null)
        {
            Console.Error.WriteLine("Cannot embed public key for symmetric (HMAC) keys.");
            return 1;
        }
        options = options with { PublicKey = publicKey };
    }

    var service = new JsfSignatureService();
    var signedJson = service.Sign(jsonInput, options);
    Console.WriteLine(signedJson);
    return 0;
});

// --- verify command ---

var verifyKeyOption = new Option<FileInfo?>("--key", "-k")
{
    Description = "Path to public/symmetric JWK file (uses embedded key if not provided)"
};

var verifyInputOption = new Option<FileInfo?>("--input", "-i")
{
    Description = "Path to signed JSON file (defaults to stdin)"
};

var verifyCommand = new Command("verify", "Verify a signed JSON document");
verifyCommand.Options.Add(verifyKeyOption);
verifyCommand.Options.Add(verifyInputOption);

verifyCommand.SetAction(parseResult =>
{
    var keyFile = parseResult.GetValue(verifyKeyOption);
    var inputFile = parseResult.GetValue(verifyInputOption);

    string jsonInput;
    if (inputFile is not null)
    {
        if (!inputFile.Exists)
        {
            Console.Error.WriteLine($"Input file not found: {inputFile.FullName}");
            return 1;
        }
        jsonInput = File.ReadAllText(inputFile.FullName);
    }
    else
    {
        jsonInput = Console.In.ReadToEnd();
    }

    var verificationOptions = new VerificationOptions();

    if (keyFile is not null)
    {
        if (!keyFile.Exists)
        {
            Console.Error.WriteLine($"Key file not found: {keyFile.FullName}");
            return 1;
        }
        var jwkJson = File.ReadAllText(keyFile.FullName);
        verificationOptions = verificationOptions with { Key = JwkKeyHelper.LoadVerificationKey(jwkJson) };
    }

    var doc = JsonNode.Parse(jsonInput)?.AsObject();
    if (doc is null)
    {
        Console.WriteLine("Invalid: Input is not a valid JSON object.");
        return 1;
    }

    var service = new JsfSignatureService();
    var result = service.Verify(doc, verificationOptions);

    if (result.IsValid)
    {
        Console.WriteLine("Valid");
        return 0;
    }
    else
    {
        Console.WriteLine($"Invalid: {result.Error}");
        return 1;
    }
});

// --- Root command ---

var rootCommand = new RootCommand("JSF CLI - JSON Format Signing tool");
rootCommand.Subcommands.Add(generateKeyCommand);
rootCommand.Subcommands.Add(signCommand);
rootCommand.Subcommands.Add(verifyCommand);

return rootCommand.Parse(args).Invoke();
