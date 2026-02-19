using System.Text.Json.Nodes;
using CoderPatros.Jsf.Cli;
using CoderPatros.Jsf.Serialization;
using FluentAssertions;

namespace CoderPatros.Jsf.Cli.Tests;

public class JwkKeyHelperTests
{
    [Theory]
    [InlineData("HS256", true)]
    [InlineData("HS384", true)]
    [InlineData("HS512", true)]
    [InlineData("ES256", false)]
    [InlineData("RS256", false)]
    [InlineData("PS256", false)]
    [InlineData("Ed25519", false)]
    public void IsSymmetricAlgorithm_ReturnsExpected(string algorithm, bool expected)
    {
        JwkKeyHelper.IsSymmetricAlgorithm(algorithm).Should().Be(expected);
    }

    [Theory]
    [InlineData("ES256", "EC", "P-256")]
    [InlineData("ES384", "EC", "P-384")]
    [InlineData("ES512", "EC", "P-521")]
    public void GenerateAsymmetricKey_EC_HasExpectedStructure(string algorithm, string expectedKty, string expectedCrv)
    {
        var (privateJwk, publicJwk) = JwkKeyHelper.GenerateAsymmetricKey(algorithm);

        var priv = JsonNode.Parse(privateJwk)!.AsObject();
        priv["kty"]!.GetValue<string>().Should().Be(expectedKty);
        priv["crv"]!.GetValue<string>().Should().Be(expectedCrv);
        priv["x"].Should().NotBeNull();
        priv["y"].Should().NotBeNull();
        priv["d"].Should().NotBeNull();

        var pub = JsonNode.Parse(publicJwk)!.AsObject();
        pub["kty"]!.GetValue<string>().Should().Be(expectedKty);
        pub["crv"]!.GetValue<string>().Should().Be(expectedCrv);
        pub["x"].Should().NotBeNull();
        pub["y"].Should().NotBeNull();
        pub["d"].Should().BeNull();
    }

    [Theory]
    [InlineData("RS256")]
    [InlineData("RS384")]
    [InlineData("RS512")]
    [InlineData("PS256")]
    [InlineData("PS384")]
    [InlineData("PS512")]
    public void GenerateAsymmetricKey_RSA_HasExpectedStructure(string algorithm)
    {
        var (privateJwk, publicJwk) = JwkKeyHelper.GenerateAsymmetricKey(algorithm);

        var priv = JsonNode.Parse(privateJwk)!.AsObject();
        priv["kty"]!.GetValue<string>().Should().Be("RSA");
        priv["n"].Should().NotBeNull();
        priv["e"].Should().NotBeNull();
        priv["d"].Should().NotBeNull();
        priv["p"].Should().NotBeNull();
        priv["q"].Should().NotBeNull();
        priv["dp"].Should().NotBeNull();
        priv["dq"].Should().NotBeNull();
        priv["qi"].Should().NotBeNull();

        var pub = JsonNode.Parse(publicJwk)!.AsObject();
        pub["kty"]!.GetValue<string>().Should().Be("RSA");
        pub["n"].Should().NotBeNull();
        pub["e"].Should().NotBeNull();
        pub["d"].Should().BeNull();
    }

    [Theory]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    public void GenerateAsymmetricKey_OKP_HasExpectedStructure(string algorithm)
    {
        var (privateJwk, publicJwk) = JwkKeyHelper.GenerateAsymmetricKey(algorithm);

        var priv = JsonNode.Parse(privateJwk)!.AsObject();
        priv["kty"]!.GetValue<string>().Should().Be("OKP");
        priv["crv"]!.GetValue<string>().Should().Be(algorithm);
        priv["x"].Should().NotBeNull();
        priv["d"].Should().NotBeNull();

        var pub = JsonNode.Parse(publicJwk)!.AsObject();
        pub["kty"]!.GetValue<string>().Should().Be("OKP");
        pub["crv"]!.GetValue<string>().Should().Be(algorithm);
        pub["x"].Should().NotBeNull();
        pub["d"].Should().BeNull();
    }

    [Theory]
    [InlineData("HS256", 32)]
    [InlineData("HS384", 48)]
    [InlineData("HS512", 64)]
    public void GenerateSymmetricKey_HasExpectedStructure(string algorithm, int expectedKeyBytes)
    {
        var jwk = JwkKeyHelper.GenerateSymmetricKey(algorithm);

        var obj = JsonNode.Parse(jwk)!.AsObject();
        obj["kty"]!.GetValue<string>().Should().Be("oct");
        obj["k"].Should().NotBeNull();

        var keyBytes = Base64UrlEncoding.Decode(obj["k"]!.GetValue<string>());
        keyBytes.Length.Should().Be(expectedKeyBytes);
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("ES384")]
    [InlineData("ES512")]
    [InlineData("RS256")]
    [InlineData("RS384")]
    [InlineData("RS512")]
    [InlineData("PS256")]
    [InlineData("PS384")]
    [InlineData("PS512")]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    public void SignVerifyRoundTrip_Asymmetric(string algorithm)
    {
        var (privateJwk, publicJwk) = JwkKeyHelper.GenerateAsymmetricKey(algorithm);

        var signingKey = JwkKeyHelper.LoadSigningKey(privateJwk);
        var verificationKey = JwkKeyHelper.LoadVerificationKey(publicJwk);

        var service = new JsfSignatureService();
        var json = """{"hello":"world"}""";

        var signed = service.Sign(json, new Models.SignatureOptions
        {
            Algorithm = algorithm,
            Key = signingKey
        });

        var doc = JsonNode.Parse(signed)!.AsObject();
        var result = service.Verify(doc, new Models.VerificationOptions
        {
            Key = verificationKey
        });

        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public void SignVerifyRoundTrip_Symmetric(string algorithm)
    {
        var jwk = JwkKeyHelper.GenerateSymmetricKey(algorithm);

        var signingKey = JwkKeyHelper.LoadSigningKey(jwk);
        var verificationKey = JwkKeyHelper.LoadVerificationKey(jwk);

        var service = new JsfSignatureService();
        var json = """{"hello":"world"}""";

        var signed = service.Sign(json, new Models.SignatureOptions
        {
            Algorithm = algorithm,
            Key = signingKey
        });

        var doc = JsonNode.Parse(signed)!.AsObject();
        var result = service.Verify(doc, new Models.VerificationOptions
        {
            Key = verificationKey
        });

        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("RS256")]
    [InlineData("Ed25519")]
    public void ExtractPublicKey_Asymmetric_ReturnsPublicKey(string algorithm)
    {
        var (privateJwk, _) = JwkKeyHelper.GenerateAsymmetricKey(algorithm);
        var publicKey = JwkKeyHelper.ExtractPublicKey(privateJwk);
        publicKey.Should().NotBeNull();
    }

    [Fact]
    public void ExtractPublicKey_Symmetric_ReturnsNull()
    {
        var jwk = JwkKeyHelper.GenerateSymmetricKey("HS256");
        var publicKey = JwkKeyHelper.ExtractPublicKey(jwk);
        publicKey.Should().BeNull();
    }

    [Fact]
    public void LoadSigningKey_InvalidJson_Throws()
    {
        var act = () => JwkKeyHelper.LoadSigningKey("not json");
        act.Should().Throw<Exception>();
    }

    [Fact]
    public void LoadSigningKey_MissingKty_Throws()
    {
        var act = () => JwkKeyHelper.LoadSigningKey("""{"k":"abc"}""");
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void LoadSigningKey_UnsupportedKty_Throws()
    {
        var act = () => JwkKeyHelper.LoadSigningKey("""{"kty":"unknown"}""");
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void LoadVerificationKey_InvalidJson_Throws()
    {
        var act = () => JwkKeyHelper.LoadVerificationKey("not json");
        act.Should().Throw<Exception>();
    }

    [Fact]
    public void LoadVerificationKey_MissingKty_Throws()
    {
        var act = () => JwkKeyHelper.LoadVerificationKey("""{"k":"abc"}""");
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void LoadVerificationKey_UnsupportedKty_Throws()
    {
        var act = () => JwkKeyHelper.LoadVerificationKey("""{"kty":"unknown"}""");
        act.Should().Throw<InvalidOperationException>();
    }
}
