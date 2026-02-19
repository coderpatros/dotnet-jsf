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

namespace CoderPatros.Jsf;

/// <summary>
/// Base exception for JSF operations.
/// </summary>
public class JsfException : Exception
{
    public JsfException(string message) : base(message) { }
    public JsfException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when signature verification fails.
/// </summary>
public sealed class JsfVerificationException : JsfException
{
    public JsfVerificationException(string message) : base(message) { }
}

/// <summary>
/// Thrown when signing fails.
/// </summary>
public sealed class JsfSigningException : JsfException
{
    public JsfSigningException(string message) : base(message) { }
    public JsfSigningException(string message, Exception innerException) : base(message, innerException) { }
}
