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

using System.Security.Cryptography;
using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Serialization;

namespace CoderPatros.Jsf.Tests.TestFixtures;

/// <summary>
/// Reference key material from the cyberphone/openkeystore JSF test vectors.
/// See: https://cyberphone.github.io/doc/security/jsf.html
/// </summary>
internal static class ReferenceKeys
{
    // EC P-256 key (example.com:p256)
    public static ECDsa CreateP256Ecdsa()
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = Base64UrlEncoding.Decode("6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU"),
                Y = Base64UrlEncoding.Decode("mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg")
            },
            D = Base64UrlEncoding.Decode("6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8")
        };
        return ECDsa.Create(parameters);
    }

    public static (SigningKey Signing, VerificationKey Verification) CreateP256()
    {
        var ecdsa = CreateP256Ecdsa();
        return (SigningKey.FromECDsa(ecdsa), VerificationKey.FromECDsa(ECDsa.Create(ecdsa.ExportParameters(false))));
    }

    // EC P-384 key (example.com:p384)
    public static ECDsa CreateP384Ecdsa()
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP384,
            Q = new ECPoint
            {
                X = Base64UrlEncoding.Decode("o4lIdIXzdJro4jU9g-2q-__i5WcutpJaWwOeSgKL8x6nxKWOPD5rH-POQhJ79l6t"),
                Y = Base64UrlEncoding.Decode("MLnyLIGdTO2feJkCW3rWWKG3elhi1Zmbp068Ejb_1LuI-2cNQsRUqb16TfK588_N")
            },
            D = Base64UrlEncoding.Decode("woqAfcmqQ5T0rD-FlnTqjXw8wLOIXACCIy4SoWwy8jiSc_BRVH5jGPwZZUyvP1vd")
        };
        return ECDsa.Create(parameters);
    }

    public static (SigningKey Signing, VerificationKey Verification) CreateP384()
    {
        var ecdsa = CreateP384Ecdsa();
        return (SigningKey.FromECDsa(ecdsa), VerificationKey.FromECDsa(ECDsa.Create(ecdsa.ExportParameters(false))));
    }

    // EC P-521 key (example.com:p521)
    public static ECDsa CreateP521Ecdsa()
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP521,
            Q = new ECPoint
            {
                X = Base64UrlEncoding.Decode("AVb-eD8V1UAzN8GWoUypQ_8xSABA4PwUZ1O_fanjLvbwpuyoniN98ljWt3y93TCrDAqe1089tLCfpJhre8M5frBs"),
                Y = Base64UrlEncoding.Decode("ABORvO-p61zLrGCtgqqqFcQJX_ljnoJ7iDd1IIKZSyksI8aElmtJFCRVSgCyU_P7mSmilqVVaBWhE9fqRHcQ2u_c")
            },
            D = Base64UrlEncoding.Decode("AUxbUwj3PKhK08nxKFFRToiriDJyp_bUv0puyt0qch9UwQ5qCjqBqSPAOB5RyvPKy0XwKDhXJGeAGsVqKzsUMRxA")
        };
        return ECDsa.Create(parameters);
    }

    public static (SigningKey Signing, VerificationKey Verification) CreateP521()
    {
        var ecdsa = CreateP521Ecdsa();
        return (SigningKey.FromECDsa(ecdsa), VerificationKey.FromECDsa(ECDsa.Create(ecdsa.ExportParameters(false))));
    }

    // RSA 2048-bit key (example.com:r2048)
    public static RSA CreateRsa2048Rsa()
    {
        var parameters = new RSAParameters
        {
            Modulus = Base64UrlEncoding.Decode("ptKZyFPStvmOlb0WihOBhlHUr6wFDHC-tW7hJAudfTQ5mHZQpB8PoMz07udZA-dG8dhUIPkmXlp1TgREeYTHdhxhuf0y_GhbpZv5JPYHx3watO-HWO2qYkjRMEcrWhPMdaVkS_Xe_liaMcow4jYoWaFm8VobeYsyVD2bWWdyl4joTEETm1Z47RnnfR15kVhVudVrDzEFmM4nXV_6dmIg184RJE4httwBFxR8qZCQCwTiJmsoyJxfUR0Gs4ePKc5sB0NTkmFZc5klQSitd67RJn2ldhbqE7EpDl4XlIt-UyLJm1guCBltia8Agke7dXuhpB7hQ6LJwY4EjzthkJ8IPw"),
            Exponent = Base64UrlEncoding.Decode("AQAB"),
            D = Base64UrlEncoding.Decode("KT6KTNAEmb5rdTPxvaOC832J0wD5opDBZcQLH8lLX6go0Tv3Rgxz5bKmn-ZMyL1GegadDiXrSYqd0_MUJuMgGWB8_OnP0D3Q4soEOBIn7DcPt0o9MUxZQsF0DraZzkR02WVRvcIFJucrAEJYAaWYJkjUVbmMb2ltwQwWO21rFHGbpE73nsfr_oAWsZEvKsQZoYm4fh5jVI5-wKyRnKaN1uqAcNgj75cdywCHBVwgEefEgOPM77CDMH0-JumSirQiBfR35-HWRwHwpm09wI6Aqtvgy5bzxvLDDRgrhX4LCPtUHGrUXNJHRKYiHQX6P6bIVuBrHV6VFpyS-5weu0w6kQ"),
            P = Base64UrlEncoding.Decode("0KOEHi7Tu0tyh_FC95V-JYR9Su_0PfbgR5ry13Yg5B4y2wW4dCX6x4B7ZyvW7ydhr1XMISPX04jtadaOUTOY24lVEgkvdbC3Ezxb_F_N7BMQWZ675UpW_72vuMlvi876-mYg5WWLFUTbzQB1E6Ix0Qjh9j-Hl9fqpeT-BTHX70k"),
            Q = Base64UrlEncoding.Decode("zLEOCwacYw_SnQ8yc8PWtMWy-O0HQnmQajVMujL8CxNPirBfqa76IoDWQmk3CdhX6D8aRN_6NAP28gk7g5H3Xa3f4XADtIHdUfQmCQ1yX5yG2X4XlJh1u0oW18qoaakClY8x_o5y6lY2xg-rc93TfgMDYFCw_778FzNk1qbvU0c"),
            DP = Base64UrlEncoding.Decode("aQ890xkPY0vNo2i4qQVtHSVHFjoYSi-LpmL_D8IbM-OFBkcuJ8aMLnOjMEOiGpFBHlJc1P9AifN0YYw54-fQfBP-c3OOo3vV5GjLhR0VC2BaJlbJFN_HSUZSOwGsGsGiHf7ZZ8onLBGdgPBPBBDzdug7KI27EJoYPWs_AoyjyIk"),
            DQ = Base64UrlEncoding.Decode("PIePE4uc615edbtsu_cJouNjjWDqaKnyHrYsPlOdXNkVCHonj9ICffmDYpgignLLbA5dAkkJgCA8Ak7gnoOnlrg4ID4zmklc3UNJjBvB2qw65E35QyPijMPYBXAUZUppTTjPG-ub59ge0msH1Hegdv8FHJJABSDBA0tbYm5zDzk"),
            InverseQ = Base64UrlEncoding.Decode("Pf9CrVihTIRd79NS-eAFxeW9eUa6AYWQH8yNVNMDzuCek8_tSqpra8B0wTyN-p8yEyIZTIXKE7DETIJ79DR88ZXEEJgMt36BQRTsh16pd4T7VmxFYgeY0LOHD-bbNaIr1YaxLa6xOdUxuFfxH3w9SSoh5ezBAmBDMgc99T7EQrs")
        };
        return RSA.Create(parameters);
    }

    public static (SigningKey Signing, VerificationKey Verification) CreateRsa2048()
    {
        var rsa = CreateRsa2048Rsa();
        return (SigningKey.FromRsa(rsa), VerificationKey.FromRsa(RSA.Create(rsa.ExportParameters(false))));
    }

    // Ed25519 key (example.com:ed25519)
    public static (byte[] PrivateKey, byte[] PublicKey) Ed25519KeyPair()
    {
        var privateKey = Base64UrlEncoding.Decode("0flr-6bXs459f9qwAq20Zs3NizTGIEH5_rTDFoumFV4");
        var publicKey = Base64UrlEncoding.Decode("_kms9bkrbpI1lPLoM2j2gKySS-k89TOuyvgC43dX-Mk");
        return (privateKey, publicKey);
    }

    public static (SigningKey Signing, VerificationKey Verification) CreateEd25519()
    {
        var (priv, pub) = Ed25519KeyPair();
        return (SigningKey.FromEdDsa(priv, "Ed25519"), VerificationKey.FromEdDsa(pub, "Ed25519"));
    }

    // Ed448 key (example.com:ed448)
    public static (byte[] PrivateKey, byte[] PublicKey) Ed448KeyPair()
    {
        var privateKey = Base64UrlEncoding.Decode("EzABSeOFsw-6ydqO3YW4ZPONZqEOQ-0DARQ1U-v_jOCyXPI6FkGS1x1a5CAVY2HNTcfNYGKBriKC");
        var publicKey = Base64UrlEncoding.Decode("IUkRrGrNQFnHA-pIcgwzTxyL4BlWyHqC6LkZbgyHMsM14mC2NfpW9QV_Ao7mkQXIZM2OCgCimEQA");
        return (privateKey, publicKey);
    }

    public static (SigningKey Signing, VerificationKey Verification) CreateEd448()
    {
        var (priv, pub) = Ed448KeyPair();
        return (SigningKey.FromEdDsa(priv, "Ed448"), VerificationKey.FromEdDsa(pub, "Ed448"));
    }

    // HMAC 256-bit key (a256bitkey)
    public static byte[] Hmac256KeyBytes() =>
        Convert.FromHexString("7fdd851a3b9d2dafc5f0d00030e22b9343900cd42ede4948568a4a2ee655291a");

    public static (SigningKey Signing, VerificationKey Verification) CreateHmac256()
    {
        var key = Hmac256KeyBytes();
        return (SigningKey.FromHmac(key), VerificationKey.FromHmac((byte[])key.Clone()));
    }

    // HMAC 384-bit key (a384bitkey)
    public static byte[] Hmac384KeyBytes() =>
        Convert.FromHexString("37b7daeedc3403eb865a506c19597a37582ad5059e08438ada8bf544ee44bb3024a15f8fa191bbe7a533a56c9fc1db1d");

    public static (SigningKey Signing, VerificationKey Verification) CreateHmac384()
    {
        var key = Hmac384KeyBytes();
        return (SigningKey.FromHmac(key), VerificationKey.FromHmac((byte[])key.Clone()));
    }

    // HMAC 512-bit key (a512bitkey)
    public static byte[] Hmac512KeyBytes() =>
        Convert.FromHexString("83d26e96b71a5dd767c215f201ef5884fb03dfe5a8ee9612d4e3c942e84d45dfdc5801cb8379958f3af600d68eba1a14e945c90f1655671f042cea7b34d53236");

    public static (SigningKey Signing, VerificationKey Verification) CreateHmac512()
    {
        var key = Hmac512KeyBytes();
        return (SigningKey.FromHmac(key), VerificationKey.FromHmac((byte[])key.Clone()));
    }
}
