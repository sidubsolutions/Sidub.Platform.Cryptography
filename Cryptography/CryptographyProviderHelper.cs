/*
 * Sidub Platform - Cryptography
 * Copyright (C) 2024 Sidub Inc.
 * All rights reserved.
 *
 * This file is part of Sidub Platform - Cryptography (the "Product").
 *
 * The Product is dual-licensed under:
 * 1. The GNU Affero General Public License version 3 (AGPLv3)
 * 2. Sidub Inc.'s Proprietary Software License Agreement (PSLA)
 *
 * You may choose to use, redistribute, and/or modify the Product under
 * the terms of either license.
 *
 * The Product is provided "AS IS" and "AS AVAILABLE," without any
 * warranties or conditions of any kind, either express or implied, including
 * but not limited to implied warranties or conditions of merchantability and
 * fitness for a particular purpose. See the applicable license for more
 * details.
 *
 * See the LICENSE.txt file for detailed license terms and conditions or
 * visit https://sidub.ca/licensing for a copy of the license texts.
 */

#region Imports

using System.Security.Cryptography;

#endregion

namespace Sidub.Platform.Cryptography
{

    /// <summary>
    /// Helper class for cryptography providers.
    /// </summary>
    public static class CryptographyProviderHelper
    {

        #region Public methods

        /// <summary>
        /// Gets an AES provider with the specified symmetric key.
        /// </summary>
        /// <param name="key">The symmetric key.</param>
        /// <returns>An AES provider.</returns>
        /// <remarks>Vulnerability - https://learn.microsoft.com/en-us/dotnet/standard/security/vulnerabilities-cbc-mode</remarks>
        public static Aes GetAesProvider(SymmetricKey? key = null)
        {
            var provider = Aes.Create();
            provider.Mode = CipherMode.CBC;
            provider.Padding = PaddingMode.PKCS7;

            if (key is not null)
            {
                provider.Key = key.Key;
            }

            return provider;
        }

        /// <summary>
        /// Gets an ECDsa provider with the specified asymmetric key.
        /// </summary>
        /// <param name="key">The asymmetric key.</param>
        /// <returns>An ECDsa provider.</returns>
        public static ECDsa GetECDsaProvider(AsymmetricKey? key = null)
        {
            var provider = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            if (key is not null)
            {
                provider.ImportSubjectPublicKeyInfo(key.PublicKey, out _);

                if (key.PrivateKey is not null)
                    provider.ImportPkcs8PrivateKey(key.PrivateKey, out _);
            }

            return provider;
        }

        /// <summary>
        /// Gets an ECDiffieHellman provider with the specified asymmetric key.
        /// </summary>
        /// <param name="key">The asymmetric key.</param>
        /// <returns>An ECDiffieHellman provider.</returns>
        public static ECDiffieHellman GetECDiffieHellmanProvider(AsymmetricKey? key = null)
        {
            var provider = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

            if (key is not null)
            {
                provider.ImportSubjectPublicKeyInfo(key.PublicKey, out _);

                if (key.PrivateKey is not null)
                    provider.ImportPkcs8PrivateKey(key.PrivateKey, out _);
            }

            return provider;
        }

        /// <summary>
        /// Gets the parameters for password-based encryption.
        /// </summary>
        /// <returns>The PBE parameters.</returns>
        public static PbeParameters GetPbeParameters()
        {
            var parameters = new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA256, 1024);

            return parameters;
        }

        #endregion

    }

}
