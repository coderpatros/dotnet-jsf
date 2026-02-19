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

public class ES6NumberSerializerTests
{
    [Theory]
    [InlineData(0.0, "0")]
    [InlineData(1.0, "1")]
    [InlineData(-1.0, "-1")]
    [InlineData(0.5, "0.5")]
    [InlineData(-0.5, "-0.5")]
    [InlineData(100.0, "100")]
    [InlineData(1e20, "100000000000000000000")]
    [InlineData(1e21, "1e+21")]
    [InlineData(1e-7, "1e-7")]
    [InlineData(1e-6, "0.000001")]
    [InlineData(1234567890.0, "1234567890")]
    [InlineData(0.1, "0.1")]
    [InlineData(0.01, "0.01")]
    [InlineData(double.MinValue, "-1.7976931348623157e+308")]
    [InlineData(double.MaxValue, "1.7976931348623157e+308")]
    [InlineData(double.Epsilon, "5e-324")]
    [InlineData(2.220446049250313e-16, "2.220446049250313e-16")]
    [InlineData(9007199254740992.0, "9007199254740992")]
    [InlineData(3.14159, "3.14159")]
    [InlineData(999999999999999900000.0, "999999999999999900000")]
    public void Serialize_ProducesES6Output(double value, string expected)
    {
        ES6NumberSerializer.Serialize(value).Should().Be(expected);
    }

    [Fact]
    public void Serialize_NegativeZero_ReturnsZero()
    {
        ES6NumberSerializer.Serialize(-0.0).Should().Be("0");
    }

    [Fact]
    public void Serialize_NaN_Throws()
    {
        var act = () => ES6NumberSerializer.Serialize(double.NaN);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Serialize_Infinity_Throws()
    {
        var act = () => ES6NumberSerializer.Serialize(double.PositiveInfinity);
        act.Should().Throw<ArgumentException>();
    }
}
