using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using CoderPatros.Jsf.Api.Models;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;

namespace CoderPatros.Jsf.Api.Tests;

public class ApiIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public ApiIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("RS256")]
    [InlineData("Ed25519")]
    public async Task GenerateKey_Asymmetric_ReturnsKeyPair(string algorithm)
    {
        var response = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm });
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        body!["privateKey"].Should().NotBeNull();
        body["publicKey"].Should().NotBeNull();
        body["symmetricKey"].Should().BeNull();
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public async Task GenerateKey_Symmetric_ReturnsSymmetricKey(string algorithm)
    {
        var response = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm });
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        body!["symmetricKey"].Should().NotBeNull();
        body["privateKey"].Should().BeNull();
        body["publicKey"].Should().BeNull();
    }

    [Fact]
    public async Task GenerateKey_InvalidAlgorithm_Returns400()
    {
        var response = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "INVALID" });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("RS256")]
    [InlineData("PS256")]
    [InlineData("Ed25519")]
    public async Task SignAndVerify_Asymmetric_RoundTrips(string algorithm)
    {
        // Generate key
        var genResponse = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm });
        var keys = await genResponse.Content.ReadFromJsonAsync<JsonObject>();
        var privateKey = keys!["privateKey"]!.AsObject();
        var publicKey = keys["publicKey"]!.AsObject();

        // Sign
        var document = JsonNode.Parse("""{"hello":"world"}""")!.AsObject();
        var signResponse = await _client.PostAsJsonAsync("/api/sign", new
        {
            document,
            algorithm,
            key = privateKey
        });
        signResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var signResult = await signResponse.Content.ReadFromJsonAsync<JsonObject>();
        var signedDoc = signResult!["document"]!.AsObject();

        // Verify
        var verifyResponse = await _client.PostAsJsonAsync("/api/verify", new
        {
            document = signedDoc,
            key = publicKey
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public async Task SignAndVerify_Symmetric_RoundTrips(string algorithm)
    {
        // Generate key
        var genResponse = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm });
        var keys = await genResponse.Content.ReadFromJsonAsync<JsonObject>();
        var symmetricKey = keys!["symmetricKey"]!.AsObject();

        // Sign
        var document = JsonNode.Parse("""{"hello":"world"}""")!.AsObject();
        var signResponse = await _client.PostAsJsonAsync("/api/sign", new
        {
            document,
            algorithm,
            key = symmetricKey
        });
        signResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var signResult = await signResponse.Content.ReadFromJsonAsync<JsonObject>();
        var signedDoc = signResult!["document"]!.AsObject();

        // Verify
        var verifyResponse = await _client.PostAsJsonAsync("/api/verify", new
        {
            document = signedDoc,
            key = symmetricKey
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public async Task Sign_WithEmbeddedPublicKey_CanVerifyWithEmbeddedKey()
    {
        var genResponse = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys = await genResponse.Content.ReadFromJsonAsync<JsonObject>();
        var privateKey = keys!["privateKey"]!.AsObject();

        var document = JsonNode.Parse("""{"hello":"world"}""")!.AsObject();
        var signResponse = await _client.PostAsJsonAsync("/api/sign", new
        {
            document,
            algorithm = "ES256",
            key = privateKey,
            embedPublicKey = true
        });
        signResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var signResult = await signResponse.Content.ReadFromJsonAsync<JsonObject>();
        var signedDoc = signResult!["document"]!.AsObject();

        var verifyResponse = await _client.PostAsJsonAsync("/api/verify", new
        {
            document = signedDoc,
            allowEmbeddedKey = true
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public async Task Verify_InvalidSignature_ReturnsInvalid()
    {
        // Generate two different key pairs
        var gen1 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys1 = await gen1.Content.ReadFromJsonAsync<JsonObject>();
        var privateKey1 = keys1!["privateKey"]!.AsObject();

        var gen2 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys2 = await gen2.Content.ReadFromJsonAsync<JsonObject>();
        var publicKey2 = keys2!["publicKey"]!.AsObject();

        // Sign with key1
        var document = JsonNode.Parse("""{"hello":"world"}""")!.AsObject();
        var signResponse = await _client.PostAsJsonAsync("/api/sign", new
        {
            document,
            algorithm = "ES256",
            key = privateKey1
        });
        var signResult = await signResponse.Content.ReadFromJsonAsync<JsonObject>();
        var signedDoc = signResult!["document"]!.AsObject();

        // Verify with key2 (wrong key)
        var verifyResponse = await _client.PostAsJsonAsync("/api/verify", new
        {
            document = signedDoc,
            key = publicKey2
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeFalse();
    }

    [Fact]
    public async Task DirectEndpoints_Sign_Works()
    {
        var genResponse = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys = await genResponse.Content.ReadFromJsonAsync<JsonObject>();
        var privateKey = keys!["privateKey"]!.AsObject();
        var publicKey = keys["publicKey"]!.AsObject();

        var document = JsonNode.Parse("""{"test":"direct"}""")!.AsObject();
        var signResponse = await _client.PostAsJsonAsync("/api/signatures/sign", new
        {
            document,
            algorithm = "ES256",
            key = privateKey
        });
        signResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var signResult = await signResponse.Content.ReadFromJsonAsync<JsonObject>();
        var signedDoc = signResult!["document"]!.AsObject();

        var verifyResponse = await _client.PostAsJsonAsync("/api/signatures/verify", new
        {
            document = signedDoc,
            key = publicKey
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public async Task AddSigner_MultiSig_Works()
    {
        // Generate two key pairs
        var gen1 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys1 = await gen1.Content.ReadFromJsonAsync<JsonObject>();
        var privKey1 = keys1!["privateKey"]!.AsObject();

        var gen2 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES384" });
        var keys2 = await gen2.Content.ReadFromJsonAsync<JsonObject>();
        var privKey2 = keys2!["privateKey"]!.AsObject();

        var document = JsonNode.Parse("""{"multi":"sig"}""")!.AsObject();

        // Add first signer
        var response1 = await _client.PostAsJsonAsync("/api/signatures/add-signer", new
        {
            document,
            algorithm = "ES256",
            key = privKey1,
            embedPublicKey = true
        });
        response1.StatusCode.Should().Be(HttpStatusCode.OK);
        var result1 = await response1.Content.ReadFromJsonAsync<JsonObject>();
        var docWith1 = result1!["document"]!.AsObject();

        // Add second signer
        var response2 = await _client.PostAsJsonAsync("/api/signatures/add-signer", new
        {
            document = docWith1,
            algorithm = "ES384",
            key = privKey2,
            embedPublicKey = true
        });
        response2.StatusCode.Should().Be(HttpStatusCode.OK);
        var result2 = await response2.Content.ReadFromJsonAsync<JsonObject>();
        var docWith2 = result2!["document"]!.AsObject();

        // Verify signers
        var verifyResponse = await _client.PostAsJsonAsync("/api/signatures/verify-signers", new
        {
            document = docWith2,
            allowEmbeddedKey = true
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public async Task AppendToChain_Works()
    {
        var gen1 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys1 = await gen1.Content.ReadFromJsonAsync<JsonObject>();
        var privKey1 = keys1!["privateKey"]!.AsObject();

        var gen2 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys2 = await gen2.Content.ReadFromJsonAsync<JsonObject>();
        var privKey2 = keys2!["privateKey"]!.AsObject();

        var document = JsonNode.Parse("""{"chain":"test"}""")!.AsObject();

        // First entry in chain
        var response1 = await _client.PostAsJsonAsync("/api/signatures/append-to-chain", new
        {
            document,
            algorithm = "ES256",
            key = privKey1,
            embedPublicKey = true
        });
        response1.StatusCode.Should().Be(HttpStatusCode.OK);
        var result1 = await response1.Content.ReadFromJsonAsync<JsonObject>();
        var docChain1 = result1!["document"]!.AsObject();

        // Second entry in chain
        var response2 = await _client.PostAsJsonAsync("/api/signatures/append-to-chain", new
        {
            document = docChain1,
            algorithm = "ES256",
            key = privKey2,
            embedPublicKey = true
        });
        response2.StatusCode.Should().Be(HttpStatusCode.OK);
        var result2 = await response2.Content.ReadFromJsonAsync<JsonObject>();
        var docChain2 = result2!["document"]!.AsObject();

        // Verify chain
        var verifyResponse = await _client.PostAsJsonAsync("/api/signatures/verify-chain", new
        {
            document = docChain2,
            allowEmbeddedKey = true
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }
}
