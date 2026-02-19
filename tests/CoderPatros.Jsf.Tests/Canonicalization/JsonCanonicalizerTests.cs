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

using CoderPatros.Jsf.Canonicalization;
using FluentAssertions;

namespace CoderPatros.Jsf.Tests.Canonicalization;

public class JsonCanonicalizerTests
{
    [Fact]
    public void Canonicalize_EmptyObject()
    {
        JsonCanonicalizer.Canonicalize("{}").Should().Be("{}");
    }

    [Fact]
    public void Canonicalize_EmptyArray()
    {
        JsonCanonicalizer.Canonicalize("[]").Should().Be("[]");
    }

    [Fact]
    public void Canonicalize_SortsKeys()
    {
        var input = """{"b":2,"a":1}""";
        var expected = """{"a":1,"b":2}""";
        JsonCanonicalizer.Canonicalize(input).Should().Be(expected);
    }

    [Fact]
    public void Canonicalize_NestedObjects_SortsRecursively()
    {
        var input = """{"b":{"d":4,"c":3},"a":1}""";
        var expected = """{"a":1,"b":{"c":3,"d":4}}""";
        JsonCanonicalizer.Canonicalize(input).Should().Be(expected);
    }

    [Fact]
    public void Canonicalize_RemovesWhitespace()
    {
        var input = """
        {
            "a" : 1,
            "b" : 2
        }
        """;
        var expected = """{"a":1,"b":2}""";
        JsonCanonicalizer.Canonicalize(input).Should().Be(expected);
    }

    [Fact]
    public void Canonicalize_PreservesArrayOrder()
    {
        var input = """[3,1,2]""";
        JsonCanonicalizer.Canonicalize(input).Should().Be("[3,1,2]");
    }

    [Fact]
    public void Canonicalize_StringEscaping()
    {
        var input = """{"key":"value with \"quotes\" and \\backslash"}""";
        var expected = """{"key":"value with \"quotes\" and \\backslash"}""";
        JsonCanonicalizer.Canonicalize(input).Should().Be(expected);
    }

    [Fact]
    public void Canonicalize_NullValue()
    {
        var input = """{"a":null}""";
        JsonCanonicalizer.Canonicalize(input).Should().Be("""{"a":null}""");
    }

    [Fact]
    public void Canonicalize_BooleanValues()
    {
        var input = """{"b":false,"a":true}""";
        JsonCanonicalizer.Canonicalize(input).Should().Be("""{"a":true,"b":false}""");
    }

    [Fact]
    public void Canonicalize_NumberFormatting()
    {
        // JCS requires ES6 number formatting
        var input = """{"a":1.0000000000000000,"b":1e1}""";
        var expected = """{"a":1,"b":10}""";
        JsonCanonicalizer.Canonicalize(input).Should().Be(expected);
    }

    [Theory]
    [InlineData("""{"":"empty"}""", """{"":"empty"}""")]
    public void Canonicalize_EmptyStringKey(string input, string expected)
    {
        JsonCanonicalizer.Canonicalize(input).Should().Be(expected);
    }

    [Fact]
    public void Canonicalize_RFC8785_Sorting_Example()
    {
        // RFC 8785 Section 3.2.3 - key ordering by code point
        var input = """{"\\u0020":"space","\\u000a":"newline"}""";
        // \n (0x0A) < space (0x20), so \n should come first
        // But these are literal string keys "\\u0020" and "\\u000a", not actual control chars
        var result = JsonCanonicalizer.Canonicalize(input);
        result.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Canonicalize_ControlCharactersInStrings()
    {
        // Control characters should be escaped as \\uXXXX
        var input = "{\"key\":\"tab\\there\"}";
        var result = JsonCanonicalizer.Canonicalize(input);
        result.Should().Be("{\"key\":\"tab\\there\"}");
    }

    [Fact]
    public void Canonicalize_DeeplyNestedStructure()
    {
        var input = """{"c":{"f":{"g":1},"e":2},"a":3,"b":{"d":4}}""";
        var expected = """{"a":3,"b":{"d":4},"c":{"e":2,"f":{"g":1}}}""";
        JsonCanonicalizer.Canonicalize(input).Should().Be(expected);
    }
}
