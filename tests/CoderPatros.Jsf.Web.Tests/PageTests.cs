using Bunit;
using CoderPatros.Jsf.Web.Pages;
using CoderPatros.Jsf.Web.Components;
using FluentAssertions;

namespace CoderPatros.Jsf.Web.Tests;

public class PageTests : TestContext
{
    [Fact]
    public void HomePage_RendersTitle()
    {
        var cut = RenderComponent<Home>();
        cut.Find("h1").TextContent.Should().Contain("JSON Signature Format");
    }

    [Fact]
    public void HomePage_ShowsPrivacyNote()
    {
        var cut = RenderComponent<Home>();
        cut.Find(".privacy-note").TextContent.Should().Contain("never leave your machine");
    }

    [Fact]
    public void HomePage_ShowsAlgorithmList()
    {
        var cut = RenderComponent<Home>();
        var markup = cut.Markup;
        markup.Should().Contain("ES256");
        markup.Should().Contain("RS256");
        markup.Should().Contain("Ed25519");
        markup.Should().Contain("HS256");
    }

    [Fact]
    public void GenerateKeyPage_RendersTitle()
    {
        var cut = RenderComponent<GenerateKey>();
        cut.Find("h1").TextContent.Should().Contain("Generate Key");
    }

    [Fact]
    public void GenerateKeyPage_HasAlgorithmSelector()
    {
        var cut = RenderComponent<GenerateKey>();
        cut.Find("select").Should().NotBeNull();
    }

    [Fact]
    public void GenerateKeyPage_HasGenerateButton()
    {
        var cut = RenderComponent<GenerateKey>();
        var button = cut.Find("button.primary");
        button.TextContent.Should().Contain("Generate Key");
    }

    [Fact]
    public void SignPage_RendersTitle()
    {
        var cut = RenderComponent<Sign>();
        cut.Find("h1").TextContent.Should().Contain("Sign a JSON Document");
    }

    [Fact]
    public void SignPage_HasSignButton()
    {
        var cut = RenderComponent<Sign>();
        var button = cut.Find("button.primary");
        button.TextContent.Should().Contain("Sign");
    }

    [Fact]
    public void VerifyPage_RendersTitle()
    {
        var cut = RenderComponent<Verify>();
        cut.Find("h1").TextContent.Should().Contain("Verify a Signed JSON Document");
    }

    [Fact]
    public void VerifyPage_HasVerifyButton()
    {
        var cut = RenderComponent<Verify>();
        var button = cut.Find("button.primary");
        button.TextContent.Should().Contain("Verify");
    }

    [Fact]
    public void AlgorithmSelector_RendersAllAlgorithms()
    {
        var cut = RenderComponent<AlgorithmSelector>();
        var options = cut.FindAll("option");

        // All 14 algorithms + 1 placeholder
        options.Count.Should().Be(15);
    }

    [Fact]
    public void ResultDisplay_WhenNotVisible_RendersNothing()
    {
        var cut = RenderComponent<ResultDisplay>(parameters => parameters
            .Add(p => p.IsVisible, false)
            .Add(p => p.IsValid, true));
        cut.Markup.Trim().Should().BeEmpty();
    }

    [Fact]
    public void ResultDisplay_WhenValid_ShowsGreen()
    {
        var cut = RenderComponent<ResultDisplay>(parameters => parameters
            .Add(p => p.IsVisible, true)
            .Add(p => p.IsValid, true));
        cut.Find(".result-valid").Should().NotBeNull();
        cut.Find(".result-valid").TextContent.Should().Contain("Valid");
    }

    [Fact]
    public void ResultDisplay_WhenInvalid_ShowsRed()
    {
        var cut = RenderComponent<ResultDisplay>(parameters => parameters
            .Add(p => p.IsVisible, true)
            .Add(p => p.IsValid, false)
            .Add(p => p.Message, "Signature mismatch"));
        cut.Find(".result-invalid").Should().NotBeNull();
        cut.Find(".result-invalid").TextContent.Should().Contain("Invalid");
        cut.Find(".result-invalid").TextContent.Should().Contain("Signature mismatch");
    }

    [Fact]
    public void KeyDisplay_WhenEmpty_RendersNothing()
    {
        var cut = RenderComponent<KeyDisplay>(parameters => parameters
            .Add(p => p.Value, ""));
        cut.Markup.Trim().Should().BeEmpty();
    }

    [Fact]
    public void KeyDisplay_WhenHasValue_ShowsContent()
    {
        var cut = RenderComponent<KeyDisplay>(parameters => parameters
            .Add(p => p.Value, """{"kty":"EC"}""")
            .Add(p => p.Label, "Test Key"));
        cut.Find(".key-display").TextContent.Should().Contain("EC");
        cut.Find("label").TextContent.Should().Contain("Test Key");
    }
}
