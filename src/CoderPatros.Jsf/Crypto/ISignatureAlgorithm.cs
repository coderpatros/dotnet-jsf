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

using CoderPatros.Jsf.Keys;

namespace CoderPatros.Jsf.Crypto;

/// <summary>
/// Abstraction for a cryptographic signature algorithm.
/// </summary>
public interface ISignatureAlgorithm
{
    string AlgorithmId { get; }
    byte[] Sign(ReadOnlySpan<byte> data, SigningKey key);
    bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key);
}
