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

using System.Text;
using CoderPatros.Jsf.Crypto;
using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Models;
using FluentAssertions;

namespace CoderPatros.Jsf.Tests.Crypto;

public class BouncyCastleAlgorithmTests
{
    private readonly SignatureAlgorithmRegistry _bcRegistry = SignatureAlgorithmRegistry.CreateBouncyCastleOnly();
    private readonly SignatureAlgorithmRegistry _nativeRegistry = new();

    [Theory]
    [InlineData(JsfAlgorithm.ES256)]
    [InlineData(JsfAlgorithm.ES384)]
    [InlineData(JsfAlgorithm.ES512)]
    public void BouncyCastleEcdsa_SignAndVerify_RoundTrips(string algorithm)
    {
        var (privateJwk, publicJwk) = BouncyCastleJwkKeyHelper.GenerateAsymmetricKey(algorithm);
        using var signing = BouncyCastleJwkKeyHelper.LoadSigningKey(privateJwk);
        using var verification = BouncyCastleJwkKeyHelper.LoadVerificationKey(publicJwk);

        var data = Encoding.UTF8.GetBytes("test data for BC ECDSA");
        var algo = _bcRegistry.Get(algorithm);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.RS256)]
    [InlineData(JsfAlgorithm.RS384)]
    [InlineData(JsfAlgorithm.RS512)]
    public void BouncyCastleRsaPkcs1_SignAndVerify_RoundTrips(string algorithm)
    {
        var (privateJwk, publicJwk) = BouncyCastleJwkKeyHelper.GenerateAsymmetricKey(algorithm);
        using var signing = BouncyCastleJwkKeyHelper.LoadSigningKey(privateJwk);
        using var verification = BouncyCastleJwkKeyHelper.LoadVerificationKey(publicJwk);

        var data = Encoding.UTF8.GetBytes("test data for BC RSA PKCS#1");
        var algo = _bcRegistry.Get(algorithm);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.PS256)]
    [InlineData(JsfAlgorithm.PS384)]
    [InlineData(JsfAlgorithm.PS512)]
    public void BouncyCastleRsaPss_SignAndVerify_RoundTrips(string algorithm)
    {
        var (privateJwk, publicJwk) = BouncyCastleJwkKeyHelper.GenerateAsymmetricKey(algorithm);
        using var signing = BouncyCastleJwkKeyHelper.LoadSigningKey(privateJwk);
        using var verification = BouncyCastleJwkKeyHelper.LoadVerificationKey(publicJwk);

        var data = Encoding.UTF8.GetBytes("test data for BC RSA-PSS");
        var algo = _bcRegistry.Get(algorithm);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.HS256)]
    [InlineData(JsfAlgorithm.HS384)]
    [InlineData(JsfAlgorithm.HS512)]
    public void BouncyCastleHmac_SignAndVerify_RoundTrips(string algorithm)
    {
        var jwk = BouncyCastleJwkKeyHelper.GenerateSymmetricKey(algorithm);
        using var signing = BouncyCastleJwkKeyHelper.LoadSigningKey(jwk);
        using var verification = BouncyCastleJwkKeyHelper.LoadVerificationKey(jwk);

        var data = Encoding.UTF8.GetBytes("test data for BC HMAC");
        var algo = _bcRegistry.Get(algorithm);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.HS256)]
    [InlineData(JsfAlgorithm.HS384)]
    [InlineData(JsfAlgorithm.HS512)]
    public void BouncyCastleHmac_IsDeterministic(string algorithm)
    {
        var jwk = BouncyCastleJwkKeyHelper.GenerateSymmetricKey(algorithm);
        using var signing = BouncyCastleJwkKeyHelper.LoadSigningKey(jwk);

        var data = Encoding.UTF8.GetBytes("deterministic test");
        var algo = _bcRegistry.Get(algorithm);

        var sig1 = algo.Sign(data, signing);
        var sig2 = algo.Sign(data, signing);

        sig1.Should().BeEquivalentTo(sig2);
    }

    [Theory]
    [InlineData(JsfAlgorithm.HS256)]
    [InlineData(JsfAlgorithm.HS384)]
    [InlineData(JsfAlgorithm.HS512)]
    public void HmacCrossCompatibility_NativeSignBcVerify(string algorithm)
    {
        var jwk = JwkKeyHelper.GenerateSymmetricKey(algorithm);
        using var nativeSigning = JwkKeyHelper.LoadSigningKey(jwk);
        using var bcVerification = BouncyCastleJwkKeyHelper.LoadVerificationKey(jwk);

        var data = Encoding.UTF8.GetBytes("cross-compat HMAC test");
        var nativeAlgo = _nativeRegistry.Get(algorithm);
        var bcAlgo = _bcRegistry.Get(algorithm);

        var signature = nativeAlgo.Sign(data, nativeSigning);
        var isValid = bcAlgo.Verify(data, signature, bcVerification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.HS256)]
    [InlineData(JsfAlgorithm.HS384)]
    [InlineData(JsfAlgorithm.HS512)]
    public void HmacCrossCompatibility_BcSignNativeVerify(string algorithm)
    {
        var jwk = BouncyCastleJwkKeyHelper.GenerateSymmetricKey(algorithm);
        using var bcSigning = BouncyCastleJwkKeyHelper.LoadSigningKey(jwk);
        using var nativeVerification = JwkKeyHelper.LoadVerificationKey(jwk);

        var data = Encoding.UTF8.GetBytes("cross-compat HMAC test");
        var bcAlgo = _bcRegistry.Get(algorithm);
        var nativeAlgo = _nativeRegistry.Get(algorithm);

        var signature = bcAlgo.Sign(data, bcSigning);
        var isValid = nativeAlgo.Verify(data, signature, nativeVerification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.RS256)]
    [InlineData(JsfAlgorithm.RS384)]
    [InlineData(JsfAlgorithm.RS512)]
    public void RsaPkcs1CrossCompatibility_NativeSignBcVerify(string algorithm)
    {
        var (privateJwk, publicJwk) = JwkKeyHelper.GenerateAsymmetricKey(algorithm);
        using var nativeSigning = JwkKeyHelper.LoadSigningKey(privateJwk);
        using var bcVerification = BouncyCastleJwkKeyHelper.LoadVerificationKey(publicJwk);

        var data = Encoding.UTF8.GetBytes("cross-compat RSA PKCS#1 test");
        var nativeAlgo = _nativeRegistry.Get(algorithm);
        var bcAlgo = _bcRegistry.Get(algorithm);

        var signature = nativeAlgo.Sign(data, nativeSigning);
        var isValid = bcAlgo.Verify(data, signature, bcVerification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.RS256)]
    [InlineData(JsfAlgorithm.RS384)]
    [InlineData(JsfAlgorithm.RS512)]
    public void RsaPkcs1CrossCompatibility_BcSignNativeVerify(string algorithm)
    {
        var (privateJwk, publicJwk) = BouncyCastleJwkKeyHelper.GenerateAsymmetricKey(algorithm);
        using var bcSigning = BouncyCastleJwkKeyHelper.LoadSigningKey(privateJwk);
        using var nativeVerification = JwkKeyHelper.LoadVerificationKey(publicJwk);

        var data = Encoding.UTF8.GetBytes("cross-compat RSA PKCS#1 test");
        var bcAlgo = _bcRegistry.Get(algorithm);
        var nativeAlgo = _nativeRegistry.Get(algorithm);

        var signature = bcAlgo.Sign(data, bcSigning);
        var isValid = nativeAlgo.Verify(data, signature, nativeVerification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.ES256)]
    [InlineData(JsfAlgorithm.ES384)]
    [InlineData(JsfAlgorithm.ES512)]
    public void EcdsaCrossCompatibility_NativeSignBcVerify(string algorithm)
    {
        var (privateJwk, publicJwk) = JwkKeyHelper.GenerateAsymmetricKey(algorithm);
        using var nativeSigning = JwkKeyHelper.LoadSigningKey(privateJwk);
        using var bcVerification = BouncyCastleJwkKeyHelper.LoadVerificationKey(publicJwk);

        var data = Encoding.UTF8.GetBytes("cross-compat ECDSA test");
        var nativeAlgo = _nativeRegistry.Get(algorithm);
        var bcAlgo = _bcRegistry.Get(algorithm);

        var signature = nativeAlgo.Sign(data, nativeSigning);
        var isValid = bcAlgo.Verify(data, signature, bcVerification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.ES256)]
    [InlineData(JsfAlgorithm.ES384)]
    [InlineData(JsfAlgorithm.ES512)]
    public void EcdsaCrossCompatibility_BcSignNativeVerify(string algorithm)
    {
        var (privateJwk, publicJwk) = BouncyCastleJwkKeyHelper.GenerateAsymmetricKey(algorithm);
        using var bcSigning = BouncyCastleJwkKeyHelper.LoadSigningKey(privateJwk);
        using var nativeVerification = JwkKeyHelper.LoadVerificationKey(publicJwk);

        var data = Encoding.UTF8.GetBytes("cross-compat ECDSA test");
        var bcAlgo = _bcRegistry.Get(algorithm);
        var nativeAlgo = _nativeRegistry.Get(algorithm);

        var signature = bcAlgo.Sign(data, bcSigning);
        var isValid = nativeAlgo.Verify(data, signature, nativeVerification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.ES256)]
    [InlineData(JsfAlgorithm.ES384)]
    [InlineData(JsfAlgorithm.ES512)]
    public void BouncyCastleEcdsa_Verify_WrongKey_ReturnsFalse(string algorithm)
    {
        var (privateJwk, _) = BouncyCastleJwkKeyHelper.GenerateAsymmetricKey(algorithm);
        var (_, wrongPublicJwk) = BouncyCastleJwkKeyHelper.GenerateAsymmetricKey(algorithm);
        using var signing = BouncyCastleJwkKeyHelper.LoadSigningKey(privateJwk);
        using var wrongVerification = BouncyCastleJwkKeyHelper.LoadVerificationKey(wrongPublicJwk);

        var data = Encoding.UTF8.GetBytes("test data");
        var algo = _bcRegistry.Get(algorithm);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, wrongVerification);

        isValid.Should().BeFalse();
    }

    [Fact]
    public void BouncyCastleHmac_Verify_WrongKey_ReturnsFalse()
    {
        var jwk1 = BouncyCastleJwkKeyHelper.GenerateSymmetricKey("HS256");
        var jwk2 = BouncyCastleJwkKeyHelper.GenerateSymmetricKey("HS256");
        using var signing = BouncyCastleJwkKeyHelper.LoadSigningKey(jwk1);
        using var wrongVerification = BouncyCastleJwkKeyHelper.LoadVerificationKey(jwk2);

        var data = Encoding.UTF8.GetBytes("test data");
        var algo = _bcRegistry.Get(JsfAlgorithm.HS256);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, wrongVerification);

        isValid.Should().BeFalse();
    }

    [Theory]
    [InlineData(JsfAlgorithm.ES256)]
    [InlineData(JsfAlgorithm.RS256)]
    [InlineData(JsfAlgorithm.PS256)]
    [InlineData(JsfAlgorithm.HS256)]
    public void BouncyCastleFullSignVerifyRoundTrip_ViaService(string algorithm)
    {
        var bcService = new JsfSignatureService(SignatureAlgorithmRegistry.CreateBouncyCastleOnly());
        var json = """{"hello":"world"}""";

        if (BouncyCastleJwkKeyHelper.IsSymmetricAlgorithm(algorithm))
        {
            var jwk = BouncyCastleJwkKeyHelper.GenerateSymmetricKey(algorithm);
            using var signingKey = BouncyCastleJwkKeyHelper.LoadSigningKey(jwk);
            using var verificationKey = BouncyCastleJwkKeyHelper.LoadVerificationKey(jwk);

            var signed = bcService.Sign(json, new SignatureOptions { Algorithm = algorithm, Key = signingKey });
            var doc = System.Text.Json.Nodes.JsonNode.Parse(signed)!.AsObject();
            var result = bcService.Verify(doc, new VerificationOptions { Key = verificationKey });
            result.IsValid.Should().BeTrue();
        }
        else
        {
            var (privateJwk, publicJwk) = BouncyCastleJwkKeyHelper.GenerateAsymmetricKey(algorithm);
            using var signingKey = BouncyCastleJwkKeyHelper.LoadSigningKey(privateJwk);
            using var verificationKey = BouncyCastleJwkKeyHelper.LoadVerificationKey(publicJwk);

            var signed = bcService.Sign(json, new SignatureOptions { Algorithm = algorithm, Key = signingKey });
            var doc = System.Text.Json.Nodes.JsonNode.Parse(signed)!.AsObject();
            var result = bcService.Verify(doc, new VerificationOptions { Key = verificationKey });
            result.IsValid.Should().BeTrue();
        }
    }
}
