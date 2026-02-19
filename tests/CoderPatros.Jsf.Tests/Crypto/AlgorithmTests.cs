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
using CoderPatros.Jsf.Tests.TestFixtures;
using FluentAssertions;

namespace CoderPatros.Jsf.Tests.Crypto;

public class AlgorithmTests
{
    private readonly SignatureAlgorithmRegistry _registry = new();

    [Theory]
    [InlineData(JsfAlgorithm.ES256)]
    [InlineData(JsfAlgorithm.ES384)]
    [InlineData(JsfAlgorithm.ES512)]
    public void Ecdsa_SignAndVerify_RoundTrips(string algorithm)
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(algorithm);
        var data = Encoding.UTF8.GetBytes("test data for ECDSA");

        var algo = _registry.Get(algorithm);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.RS256)]
    [InlineData(JsfAlgorithm.RS384)]
    [InlineData(JsfAlgorithm.RS512)]
    public void RsaPkcs1_SignAndVerify_RoundTrips(string algorithm)
    {
        var (signing, verification, _) = KeyFixtures.CreateRsaKeySet();
        var data = Encoding.UTF8.GetBytes("test data for RSA PKCS#1");

        var algo = _registry.Get(algorithm);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.PS256)]
    [InlineData(JsfAlgorithm.PS384)]
    [InlineData(JsfAlgorithm.PS512)]
    public void RsaPss_SignAndVerify_RoundTrips(string algorithm)
    {
        var (signing, verification, _) = KeyFixtures.CreateRsaKeySet();
        var data = Encoding.UTF8.GetBytes("test data for RSA-PSS");

        var algo = _registry.Get(algorithm);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.HS256)]
    [InlineData(JsfAlgorithm.HS384)]
    [InlineData(JsfAlgorithm.HS512)]
    public void Hmac_SignAndVerify_RoundTrips(string algorithm)
    {
        var (signing, verification) = KeyFixtures.CreateHmacKeySet(algorithm);
        var data = Encoding.UTF8.GetBytes("test data for HMAC");

        var algo = _registry.Get(algorithm);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.HS256)]
    [InlineData(JsfAlgorithm.HS384)]
    [InlineData(JsfAlgorithm.HS512)]
    public void Hmac_IsDeterministic(string algorithm)
    {
        var keys = KeyFixtures.CreateHmacKeySet(algorithm);
        var signing = keys.Signing;

        var data = Encoding.UTF8.GetBytes("deterministic test");
        var algo = _registry.Get(algorithm);

        var sig1 = algo.Sign(data, signing);
        var sig2 = algo.Sign(data, signing);

        sig1.Should().BeEquivalentTo(sig2);
    }

    [Fact]
    public void Ed25519_SignAndVerify_RoundTrips()
    {
        var (signing, verification, _) = KeyFixtures.CreateEdDsaKeySet("Ed25519");
        var data = Encoding.UTF8.GetBytes("test data for Ed25519");

        var algo = _registry.Get(JsfAlgorithm.Ed25519);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Fact]
    public void Ed448_SignAndVerify_RoundTrips()
    {
        var (signing, verification, _) = KeyFixtures.CreateEdDsaKeySet("Ed448");
        var data = Encoding.UTF8.GetBytes("test data for Ed448");

        var algo = _registry.Get(JsfAlgorithm.Ed448);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, verification);

        isValid.Should().BeTrue();
    }

    [Fact]
    public void Ecdsa_Verify_WrongKey_ReturnsFalse()
    {
        var (signing, _, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (_, wrongVerification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var data = Encoding.UTF8.GetBytes("test data");

        var algo = _registry.Get(JsfAlgorithm.ES256);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, wrongVerification);

        isValid.Should().BeFalse();
    }

    [Fact]
    public void Hmac_Verify_WrongKey_ReturnsFalse()
    {
        var (signing, _) = KeyFixtures.CreateHmacKeySet(JsfAlgorithm.HS256);
        var (_, wrongVerification) = KeyFixtures.CreateHmacKeySet(JsfAlgorithm.HS256);
        var data = Encoding.UTF8.GetBytes("test data");

        var algo = _registry.Get(JsfAlgorithm.HS256);
        var signature = algo.Sign(data, signing);
        var isValid = algo.Verify(data, signature, wrongVerification);

        isValid.Should().BeFalse();
    }

    [Fact]
    public void Registry_UnknownAlgorithm_Throws()
    {
        var act = () => _registry.Get("UNKNOWN");
        act.Should().Throw<JsfException>();
    }
}
