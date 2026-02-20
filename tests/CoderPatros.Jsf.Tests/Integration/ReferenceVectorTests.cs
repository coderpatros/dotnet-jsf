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
using CoderPatros.Jsf.Models;
using CoderPatros.Jsf.Tests.TestFixtures;
using FluentAssertions;

namespace CoderPatros.Jsf.Tests.Integration;

/// <summary>
/// Verifies this implementation against the official JSF test vectors from
/// https://cyberphone.github.io/doc/security/jsf.html
/// (source: https://github.com/cyberphone/openkeystore/tree/master/testdata/json-signatures)
///
/// For deterministic algorithms (RS256, Ed25519, Ed448, HMAC), these tests also
/// verify that signing with the reference keys produces byte-identical signatures.
/// </summary>
public class ReferenceVectorTests
{
    private readonly JsfSignatureService _service = new();

    private static JsonObject CreateReferenceDocument() =>
        new()
        {
            ["now"] = "2019-02-10T11:23:06Z",
            ["name"] = "Joe",
            ["id"] = 2200063
        };

    // ── ES256 (P-256) ────────────────────────────────────────────────

    [Fact]
    public void Verify_ES256_EmbeddedPublicKey()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "ES256",
                "publicKey": {
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
                  "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg"
                },
                "value": "ybT1qz5zHNi4Ndc6y7Zhamuf51IqXkPkZwjH1XcC-KSuBiaQplTw6Jasf2MbCLg3CF7PAdnMO__WSLwvI5r2jA"
              }
            }
            """;
        VerifyReferenceVector(json, new VerificationOptions { AllowEmbeddedPublicKey = true });
    }

    [Fact]
    public void Verify_ES256_KeyId()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "ES256",
                "keyId": "example.com:p256",
                "value": "Il-GTiAwCgAX3X9IC7AWfVzySWA18ZLGgHgj3KDfp0-1XsjkVDdypdIFjE9vWdieI6-pHabo6UzcYGubFSVS_w"
              }
            }
            """;
        var (_, verification) = ReferenceKeys.CreateP256();
        VerifyReferenceVector(json, new VerificationOptions { Key = verification });
    }

    [Fact]
    public void Verify_ES256_ImplicitKey()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "ES256",
                "value": "0nJX_Ek5PRjV0mQN19E5Hcfdjf_T-I49E0AzJD6VYFq-3PxHXlF6cn52VfOZN9brFfURXV9INiYrB--9v4Ly1Q"
              }
            }
            """;
        var (_, verification) = ReferenceKeys.CreateP256();
        VerifyReferenceVector(json, new VerificationOptions { Key = verification });
    }

    // ── ES384 (P-384) ────────────────────────────────────────────────

    [Fact]
    public void Verify_ES384_EmbeddedPublicKey()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "ES384",
                "publicKey": {
                  "kty": "EC",
                  "crv": "P-384",
                  "x": "o4lIdIXzdJro4jU9g-2q-__i5WcutpJaWwOeSgKL8x6nxKWOPD5rH-POQhJ79l6t",
                  "y": "MLnyLIGdTO2feJkCW3rWWKG3elhi1Zmbp068Ejb_1LuI-2cNQsRUqb16TfK588_N"
                },
                "value": "OxXAQrGMw1F_PaSnsqDs2y2waf6N9UAR79XgL8lFhkVyHW2m1gyjriLRJUtH6lG3fts_zzhrCLUoLo4dQTFzRPrNilSWaMSyH6BIHldfA-DWE--Pe-o5yHKrEQ97mCcq"
              }
            }
            """;
        VerifyReferenceVector(json, new VerificationOptions { AllowEmbeddedPublicKey = true });
    }

    [Fact]
    public void Verify_ES384_KeyId()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "ES384",
                "keyId": "example.com:p384",
                "value": "GVCa3WHgNlpW39Aj9X4V2pIng9305zsDZwcv6FCpRRSgfVI3oj0a_GKEKGPHcdkg5efX1mcm9PsY5Puhbx7sDF8I0LyPXncpL2JT5LPekC1qCyGZjQKrVUnuHeCf3zdO"
              }
            }
            """;
        var (_, verification) = ReferenceKeys.CreateP384();
        VerifyReferenceVector(json, new VerificationOptions { Key = verification });
    }

    [Fact]
    public void Verify_ES384_ImplicitKey()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "ES384",
                "value": "vH3otMMlnOX7TgkgF39xhJuXtYlevK0m6_Xk9ueYqO_p4jZccOGLAifXlfALnGYlrcwb4-yfptpjI0MIpqW5D4GQ9s-Lac5t9X1y5RbY8o27-M9qRx8-G-R4BuGy74nq"
              }
            }
            """;
        var (_, verification) = ReferenceKeys.CreateP384();
        VerifyReferenceVector(json, new VerificationOptions { Key = verification });
    }

    // ── ES512 (P-521) ────────────────────────────────────────────────

    [Fact]
    public void Verify_ES512_EmbeddedPublicKey()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "ES512",
                "publicKey": {
                  "kty": "EC",
                  "crv": "P-521",
                  "x": "AVb-eD8V1UAzN8GWoUypQ_8xSABA4PwUZ1O_fanjLvbwpuyoniN98ljWt3y93TCrDAqe1089tLCfpJhre8M5frBs",
                  "y": "ABORvO-p61zLrGCtgqqqFcQJX_ljnoJ7iDd1IIKZSyksI8aElmtJFCRVSgCyU_P7mSmilqVVaBWhE9fqRHcQ2u_c"
                },
                "value": "AarnKZEM1hfLd4hpeDguOMV0wAX-7r3z7qRG6RR1MNy3ypliYFSrziQoV1bSYiy7B7VbULQPvtcjhtIAqjRPqaMMAOxplmbKUQNsHQcTxSfrX5jmHbxI_XZpaKv0Fagl7lNmlnHcRx9eeO7Vq8aqIlhQ1afYy34-fTjxHBwe0kNEkyqN"
              }
            }
            """;
        VerifyReferenceVector(json, new VerificationOptions { AllowEmbeddedPublicKey = true });
    }

    [Fact]
    public void Verify_ES512_KeyId()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "ES512",
                "keyId": "example.com:p521",
                "value": "ABePs8Mek8iGGi5CX9FHoLcezTYzY1WRLi_QVgHLPN-bzKUhsGbTDEpebHlB1yv0k9kAe1TAXMJAmB0pSDTkM5wFAaY58KJkfvQAKjQHztYFn4Z4DOPiOXG_18azwKGwynzV6-9XFSd1mcH7R42KZxhIvRGQTKpSLHPxyiSxEH1ccLGh"
              }
            }
            """;
        var (_, verification) = ReferenceKeys.CreateP521();
        VerifyReferenceVector(json, new VerificationOptions { Key = verification });
    }

    [Fact]
    public void Verify_ES512_ImplicitKey()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "ES512",
                "value": "AHXuqzN7f0IPEcgyJCEJdNS18ITiyt1q7zOMzGlh7ZIDMfOsqY_tx-HMua9UrlMRIEzPJAQqjZKiAgoFwLcBP6yQAQyX_-Ver--u9lEqX566AViazxua-DVPAFpUXGG8Pe5Ju5vikkNNGFQFcQsA5l3g7NZO_OOzkgscZhgX7psl6vsN"
              }
            }
            """;
        var (_, verification) = ReferenceKeys.CreateP521();
        VerifyReferenceVector(json, new VerificationOptions { Key = verification });
    }

    // ── RS256 (RSA 2048, PKCS#1 v1.5) ───────────────────────────────

    [Fact]
    public void Verify_RS256_EmbeddedPublicKey()
    {
        VerifyReferenceVector(Rs256JwkJson, new VerificationOptions { AllowEmbeddedPublicKey = true });
    }

    [Fact]
    public void Verify_RS256_KeyId()
    {
        VerifyReferenceVector(Rs256KidJson, new VerificationOptions { Key = ReferenceKeys.CreateRsa2048().Verification });
    }

    [Fact]
    public void Verify_RS256_ImplicitKey()
    {
        VerifyReferenceVector(Rs256ImpJson, new VerificationOptions { Key = ReferenceKeys.CreateRsa2048().Verification });
    }

    [Fact]
    public void Sign_RS256_EmbeddedPublicKey_ProducesReferenceSignature()
    {
        var rsa = ReferenceKeys.CreateRsa2048Rsa();
        var jwk = JwkKeyConverter.FromRsa(rsa);
        VerifyDeterministicSigning(Rs256JwkJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = SigningKey.FromRsa(rsa),
            PublicKey = jwk
        });
    }

    [Fact]
    public void Sign_RS256_KeyId_ProducesReferenceSignature()
    {
        var rsa = ReferenceKeys.CreateRsa2048Rsa();
        VerifyDeterministicSigning(Rs256KidJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = SigningKey.FromRsa(rsa),
            KeyId = "example.com:r2048"
        });
    }

    [Fact]
    public void Sign_RS256_ImplicitKey_ProducesReferenceSignature()
    {
        var rsa = ReferenceKeys.CreateRsa2048Rsa();
        VerifyDeterministicSigning(Rs256ImpJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = SigningKey.FromRsa(rsa)
        });
    }

    // ── PS256 (RSA 2048, PSS) ────────────────────────────────────────

    [Fact]
    public void Verify_PS256_EmbeddedPublicKey()
    {
        const string json = """
            {
              "now": "2019-02-10T11:23:06Z",
              "name": "Joe",
              "id": 2200063,
              "signature": {
                "algorithm": "PS256",
                "publicKey": {
                  "kty": "RSA",
                  "n": "ptKZyFPStvmOlb0WihOBhlHUr6wFDHC-tW7hJAudfTQ5mHZQpB8PoMz07udZA-dG8dhUIPkmXlp1TgREeYTHdhxhuf0y_GhbpZv5JPYHx3watO-HWO2qYkjRMEcrWhPMdaVkS_Xe_liaMcow4jYoWaFm8VobeYsyVD2bWWdyl4joTEETm1Z47RnnfR15kVhVudVrDzEFmM4nXV_6dmIg184RJE4httwBFxR8qZCQCwTiJmsoyJxfUR0Gs4ePKc5sB0NTkmFZc5klQSitd67RJn2ldhbqE7EpDl4XlIt-UyLJm1guCBltia8Agke7dXuhpB7hQ6LJwY4EjzthkJ8IPw",
                  "e": "AQAB"
                },
                "value": "SJnq3uAhfcDFv5MLCDhmfGE9_QQG5iDoF6urZp4uvOq-wGPDujImXHNs38XMPCQJVvDIf9Pdw1udXJAUCMkuWL0fBpMeBLriydIYNml4FOGJJ3506I3Hqk-zdjVwfBrguHshS1hniMzTqo8dzlPWxgPzU0KTDeg2xTuXOs2rbvENyqym-jHgn_iCMBQIWCwA5nQIxVmVVHNqF_wY5aUJcO1ySSWVsBk7P2_NpHNO_dOPaxdvvCvrbRne226edD4mOb6adtHoIdXVIhpsulkGEefBnqXQYvmjq_62rnCTZCfXTfM2ylp98NNgT_hyj1IN4yA5Wxwq86UP9of9yOxQ4w"
              }
            }
            """;
        VerifyReferenceVector(json, new VerificationOptions { AllowEmbeddedPublicKey = true });
    }

    // ── Ed25519 ──────────────────────────────────────────────────────

    [Fact]
    public void Verify_Ed25519_EmbeddedPublicKey()
    {
        VerifyReferenceVector(Ed25519JwkJson, new VerificationOptions { AllowEmbeddedPublicKey = true });
    }

    [Fact]
    public void Verify_Ed25519_KeyId()
    {
        VerifyReferenceVector(Ed25519KidJson, new VerificationOptions { Key = ReferenceKeys.CreateEd25519().Verification });
    }

    [Fact]
    public void Verify_Ed25519_ImplicitKey()
    {
        VerifyReferenceVector(Ed25519ImpJson, new VerificationOptions { Key = ReferenceKeys.CreateEd25519().Verification });
    }

    [Fact]
    public void Sign_Ed25519_EmbeddedPublicKey_ProducesReferenceSignature()
    {
        var (priv, pub) = ReferenceKeys.Ed25519KeyPair();
        var jwk = JwkKeyConverter.FromEdDsa(pub, "Ed25519");
        VerifyDeterministicSigning(Ed25519JwkJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.Ed25519,
            Key = SigningKey.FromEdDsa(priv, "Ed25519"),
            PublicKey = jwk
        });
    }

    [Fact]
    public void Sign_Ed25519_KeyId_ProducesReferenceSignature()
    {
        var (priv, _) = ReferenceKeys.Ed25519KeyPair();
        VerifyDeterministicSigning(Ed25519KidJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.Ed25519,
            Key = SigningKey.FromEdDsa(priv, "Ed25519"),
            KeyId = "example.com:ed25519"
        });
    }

    [Fact]
    public void Sign_Ed25519_ImplicitKey_ProducesReferenceSignature()
    {
        var (priv, _) = ReferenceKeys.Ed25519KeyPair();
        VerifyDeterministicSigning(Ed25519ImpJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.Ed25519,
            Key = SigningKey.FromEdDsa(priv, "Ed25519")
        });
    }

    // ── Ed448 ────────────────────────────────────────────────────────

    [Fact]
    public void Verify_Ed448_EmbeddedPublicKey()
    {
        VerifyReferenceVector(Ed448JwkJson, new VerificationOptions { AllowEmbeddedPublicKey = true });
    }

    [Fact]
    public void Verify_Ed448_KeyId()
    {
        VerifyReferenceVector(Ed448KidJson, new VerificationOptions { Key = ReferenceKeys.CreateEd448().Verification });
    }

    [Fact]
    public void Verify_Ed448_ImplicitKey()
    {
        VerifyReferenceVector(Ed448ImpJson, new VerificationOptions { Key = ReferenceKeys.CreateEd448().Verification });
    }

    [Fact]
    public void Sign_Ed448_EmbeddedPublicKey_ProducesReferenceSignature()
    {
        var (priv, pub) = ReferenceKeys.Ed448KeyPair();
        var jwk = JwkKeyConverter.FromEdDsa(pub, "Ed448");
        VerifyDeterministicSigning(Ed448JwkJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.Ed448,
            Key = SigningKey.FromEdDsa(priv, "Ed448"),
            PublicKey = jwk
        });
    }

    [Fact]
    public void Sign_Ed448_KeyId_ProducesReferenceSignature()
    {
        var (priv, _) = ReferenceKeys.Ed448KeyPair();
        VerifyDeterministicSigning(Ed448KidJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.Ed448,
            Key = SigningKey.FromEdDsa(priv, "Ed448"),
            KeyId = "example.com:ed448"
        });
    }

    [Fact]
    public void Sign_Ed448_ImplicitKey_ProducesReferenceSignature()
    {
        var (priv, _) = ReferenceKeys.Ed448KeyPair();
        VerifyDeterministicSigning(Ed448ImpJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.Ed448,
            Key = SigningKey.FromEdDsa(priv, "Ed448")
        });
    }

    // ── HMAC ─────────────────────────────────────────────────────────

    [Fact]
    public void Verify_HS256_KeyId()
    {
        VerifyReferenceVector(Hs256KidJson, new VerificationOptions { Key = ReferenceKeys.CreateHmac256().Verification });
    }

    [Fact]
    public void Verify_HS384_KeyId()
    {
        VerifyReferenceVector(Hs384KidJson, new VerificationOptions { Key = ReferenceKeys.CreateHmac384().Verification });
    }

    [Fact]
    public void Verify_HS512_KeyId()
    {
        VerifyReferenceVector(Hs512KidJson, new VerificationOptions { Key = ReferenceKeys.CreateHmac512().Verification });
    }

    [Fact]
    public void Sign_HS256_ProducesReferenceSignature()
    {
        VerifyDeterministicSigning(Hs256KidJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.HS256,
            Key = SigningKey.FromHmac(ReferenceKeys.Hmac256KeyBytes()),
            KeyId = "a256bitkey"
        });
    }

    [Fact]
    public void Sign_HS384_ProducesReferenceSignature()
    {
        VerifyDeterministicSigning(Hs384KidJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.HS384,
            Key = SigningKey.FromHmac(ReferenceKeys.Hmac384KeyBytes()),
            KeyId = "a384bitkey"
        });
    }

    [Fact]
    public void Sign_HS512_ProducesReferenceSignature()
    {
        VerifyDeterministicSigning(Hs512KidJson, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.HS512,
            Key = SigningKey.FromHmac(ReferenceKeys.Hmac512KeyBytes()),
            KeyId = "a512bitkey"
        });
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private void VerifyReferenceVector(string json, VerificationOptions options)
    {
        var doc = JsonNode.Parse(json)!.AsObject();
        var result = _service.Verify(doc, options);
        result.IsValid.Should().BeTrue(result.Error ?? string.Empty);
    }

    /// <summary>
    /// For deterministic algorithms, verifies that signing the reference data with
    /// the reference key produces the exact same signature value as the test vector.
    /// </summary>
    private void VerifyDeterministicSigning(string expectedJson, SignatureOptions options)
    {
        var expected = JsonNode.Parse(expectedJson)!.AsObject();
        var expectedValue = expected["signature"]!.AsObject()["value"]!.GetValue<string>();

        var doc = CreateReferenceDocument();
        var signed = _service.Sign(doc, options);
        var actualValue = signed["signature"]!.AsObject()["value"]!.GetValue<string>();

        actualValue.Should().Be(expectedValue);
    }

    // ── Reference vector JSON (deterministic algorithms) ─────────────
    // Stored as fields so they can be shared between Verify and Sign tests.

    private const string Rs256JwkJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "RS256",
            "publicKey": {
              "kty": "RSA",
              "n": "ptKZyFPStvmOlb0WihOBhlHUr6wFDHC-tW7hJAudfTQ5mHZQpB8PoMz07udZA-dG8dhUIPkmXlp1TgREeYTHdhxhuf0y_GhbpZv5JPYHx3watO-HWO2qYkjRMEcrWhPMdaVkS_Xe_liaMcow4jYoWaFm8VobeYsyVD2bWWdyl4joTEETm1Z47RnnfR15kVhVudVrDzEFmM4nXV_6dmIg184RJE4httwBFxR8qZCQCwTiJmsoyJxfUR0Gs4ePKc5sB0NTkmFZc5klQSitd67RJn2ldhbqE7EpDl4XlIt-UyLJm1guCBltia8Agke7dXuhpB7hQ6LJwY4EjzthkJ8IPw",
              "e": "AQAB"
            },
            "value": "IbTdSjKTYiFa-OP4m4wynLLHFxRgY0jwr7lonUIAG8zRpiX9d0ffR_ynGGjchtHH5CtXjfiKtWau0hqejmLqOHzx0I9xcDOLy42aOzBwITU7dElpsXSVYB76i5ekh2pD-swPJ_7E3aIfL1FPDiHjmbxWEjQseifSri4OX27iMqZVjfwIVSA-xKc-_C40r_eDwtB8tdJRaMDnI-Fsu1xf8X7mAiCjhqwRTqEWEySaXN-yGtLgi_ee0OemaBsY7fD2YnL9l9k4fq_A0JwoedRK26VLzoI1HfJ1uK-lrtud0_Ne7IXfZTeZDSKoPHY1LDVzVm0asVvkB10NrLRHO4hDYg"
          }
        }
        """;

    private const string Rs256KidJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "RS256",
            "keyId": "example.com:r2048",
            "value": "Ra3r-1ZGBh-UkMzjyS70mRuw3LmC7E8TmG5y0V7EIZrnvz5lfqXl0DL20ftSpbwzFPAlkH_iywKH9g85e5TYQUlMsI7ptsjNURQv-2dRbOq4UhCjbxA8T33424tfraHMutKhJ4vhHhvDgYLqDg9Pwh2RrgcXrBc5VgCAFSR2mhzkjzyJlrOekByf6q9MyPpMjok6wBDkEoWQ8c2vEdEbck6kARYEr3AeOTsnsUptkgbsJ2xQ4ZK4Al93LMW6xiuIa1ATuYwNUilWDhJqYUnAEA54uYRNEFULYqLRjBIGipnFtz7-802K1DfjUtHSL7unwZRNg5CtFHlWAeJ8rhv-mA"
          }
        }
        """;

    private const string Rs256ImpJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "RS256",
            "value": "X6k3LmtM2UT4N13yu-vUBdM84hfYZDbxRdt49WacS3OAbYzHE33XZK5i8J7enIzvZEggxeIhQ1Wu2LpTqxNgZEjAo7qYNl4W3rilme0KNH-NnB-4BHQawqCv9_uzKnFt3MwK_nyc-Wl-7ngKrL2LvbLgY4i1GM8u0vBB_92QDMYrqVC3S6nRh9IUaQcLShyAiSMa6BwbEg0mAZgGZxMsu2tEXvNyyrYV0Z4Fsl_SMVon_kXCAFuJB-WpdpIan6GGQ1wrSkHXu4OZjvabO0qIqkE3aP2WWUPCfHbtI-Z0Iq4N3U5D56-Y8Q6OUWBWkd4kt3dAD1Q2OBbA42sKUGROnw"
          }
        }
        """;

    private const string Ed25519JwkJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "Ed25519",
            "publicKey": {
              "kty": "OKP",
              "crv": "Ed25519",
              "x": "_kms9bkrbpI1lPLoM2j2gKySS-k89TOuyvgC43dX-Mk"
            },
            "value": "UtN9-gMgTkfAdBJRX4gi0s6iKYiilO5EmXRD4KRSEnPKo5Og1ltbGYZecdJqKphCXkboIE_pecfszHEQXeqqDA"
          }
        }
        """;

    private const string Ed25519KidJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "Ed25519",
            "keyId": "example.com:ed25519",
            "value": "Z5GCvK_W6s1aiEVHlLlqlc2Q-Hq07lOkSIjKVdhjwBHnATwevYfZ8GbooHjjbN8Eb0JN-E4zT40dbGi6TnjPCA"
          }
        }
        """;

    private const string Ed25519ImpJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "Ed25519",
            "value": "VIjBJ-x4A7wPf0QiPBEvLEcPLfuMPJzaxooHPk3I65Vst2j1YYZvfc7T83oiujkUyCRbJrY5qX4rCk-OVFEmCw"
          }
        }
        """;

    private const string Ed448JwkJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "Ed448",
            "publicKey": {
              "kty": "OKP",
              "crv": "Ed448",
              "x": "IUkRrGrNQFnHA-pIcgwzTxyL4BlWyHqC6LkZbgyHMsM14mC2NfpW9QV_Ao7mkQXIZM2OCgCimEQA"
            },
            "value": "7etBe_-_lSMU1OXH38PRmT3MHvnf0IQcvX2GX-l16Ax7_-V7l0TDH31-ioXo0B8PV75PspWEm3-AVHmKpIUAbb8FU1k7KJcCc1m0HQOvbiDlIh3j_G10wrv5edpjDWBQ8Xjek94vGpKM7kA9Y--EkS4A"
          }
        }
        """;

    private const string Ed448KidJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "Ed448",
            "keyId": "example.com:ed448",
            "value": "OCU7mH_M9lf1hOKMhQBTqOOhSQRiKg9GyIGk-D1c1T5bnon7v0Mfi879N4vtA4KSuExxfUUldnQAaEWNLdTgVp8ojm2WVieRAwgAlxddJ9KMqdcXoi-SJxLByySUG-UJj3MiJmW7hhRzergMTj31-y4A"
          }
        }
        """;

    private const string Ed448ImpJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "Ed448",
            "value": "SUjAWwmGUVzFkjUBs4FPCgrikPWyivcqLIlzADGgT8m4LwAvmLDSTdn8URgML5egnUDqLzBHeGqA_H_t6z-ziw6EkgSdj88Uf_q2psWsQdltfe4EXuGjCgK5VTGgO1leN952xO9gjJD2KvofANdKsRsA"
          }
        }
        """;

    private const string Hs256KidJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "HS256",
            "keyId": "a256bitkey",
            "value": "GJ6Jhb-PfHpN6KPcjHBNxbO9j56ShgUh13JfmZ3ORkI"
          }
        }
        """;

    private const string Hs384KidJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "HS384",
            "keyId": "a384bitkey",
            "value": "FjkRAZS-HsGsC_WPKsF2fmaNO7CPp90asbgXfOPQjolyK_qQaOuJH_u7PgonjzN9"
          }
        }
        """;

    private const string Hs512KidJson = """
        {
          "now": "2019-02-10T11:23:06Z",
          "name": "Joe",
          "id": 2200063,
          "signature": {
            "algorithm": "HS512",
            "keyId": "a512bitkey",
            "value": "VJHJXrZhVMMWTKTJktmdE5J4xBjKwtdf25eItui4fIGuyYsiZD5M9n573WZ0XgM9q48gG1KpTee4q8LCW4a7qQ"
          }
        }
        """;
}
