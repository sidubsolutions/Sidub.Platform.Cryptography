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

using Microsoft.Extensions.DependencyInjection;
using Sidub.Platform.Core;
using Sidub.Platform.Core.Services;
using Sidub.Platform.Cryptography.Connectors;
using Sidub.Platform.Cryptography.Providers;
using Sidub.Platform.Cryptography.Services;
using Sidub.Platform.Cryptography.Test.Models;

namespace Sidub.Platform.Cryptography.Test
{
    [TestClass]
    public class SymmetricCryptographyTest
    {

        private readonly CryptographyServiceReference CryptographyServiceReference = new CryptographyServiceReference("core");

        private readonly IServiceRegistry _serviceRegistry;
        private readonly ICryptographyService _cryptographyService;
        private readonly CryptographyProviderBase _keyProvider;

        public SymmetricCryptographyTest()
        {
            // initialize dependency injection environment...
            var serviceCollection = new ServiceCollection();
            serviceCollection.AddSidubPlatform(serviceProvider =>
            {
                var metadata = new InMemoryServiceRegistry();

                var cryptographyReference = CryptographyServiceReference;
                //var keyConnector = new FilesystemKeyConnector(@"C:\Keys\");
                var keyConnector = new EphemeralKeyConnector();
                metadata.RegisterServiceReference(cryptographyReference, keyConnector);

                return metadata;
            });

            serviceCollection.AddSidubCryptography();

            var serviceProvider = serviceCollection.BuildServiceProvider();

            _serviceRegistry = serviceProvider.GetService<IServiceRegistry>() ?? throw new Exception("IServiceRegistry not initialized.");
            _cryptographyService = serviceProvider.GetService<ICryptographyService>() ?? throw new Exception("ICryptographyService not initialized.");

            var provider = _cryptographyService.GetProvider(CryptographyServiceReference);

            if (provider is not CryptographyProviderBase baseProvider)
                throw new Exception("Unit tests currently only support base cryptography implementation.");

            _keyProvider = baseProvider;
        }

        [TestMethod]
        public async Task SymmetricCryptographyTest_EncryptData01()
        {
            // create a key to use...
            var keyId = await _cryptographyService.CreateSymmetricKey(CryptographyServiceReference);
            var data = "this is some text";

            var encrypted = await _cryptographyService.EncryptData(CryptographyServiceReference, keyId, System.Text.Encoding.UTF8.GetBytes(data));
            var decrypted = await _cryptographyService.DecryptData(CryptographyServiceReference, keyId, encrypted);
            var decryptedString = System.Text.Encoding.UTF8.GetString(decrypted);

            Assert.AreEqual(data, decryptedString);
        }

        [TestMethod]
        public async Task SymmetricCryptographyTest_EncryptEntity01()
        {
            // create a key to use...
            var keyId = await _cryptographyService.CreateSymmetricKey(CryptographyServiceReference);
            var data = new TestSignedEntity()
            {
                TestField = "SomeTestValue"
            };

            var encrypted = await _cryptographyService.EncryptEntity(CryptographyServiceReference, keyId, data);
            var decrypted = await _cryptographyService.DecryptEntity(CryptographyServiceReference, keyId, encrypted);

            Assert.AreEqual(data.TestField, decrypted.TestField);
        }

    }
}