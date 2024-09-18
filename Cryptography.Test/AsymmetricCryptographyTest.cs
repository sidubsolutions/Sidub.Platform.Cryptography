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
    public class AsymmetricCryptographyTest
    {

        private readonly CryptographyServiceReference CryptographyServiceReference = new("core");
        private readonly IServiceRegistry _serviceRegistry;
        private readonly ICryptographyService _cryptographyService;
        private readonly CryptographyProviderBase _keyProvider;

        public AsymmetricCryptographyTest()
        {
            // initialize dependency injection environment...
            var serviceCollection = new ServiceCollection();
            serviceCollection.AddSidubPlatform(serviceProvider =>
            {
                var metadata = new InMemoryServiceRegistry();

                var cryptographyReference = CryptographyServiceReference;
                var keyConnector = new EphemeralKeyConnector();
                //var keyConnector = new FilesystemKeyConnector(@"C:\Keys\");
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
        public async Task AsymmetricCryptographyTest_SignData01()
        {
            // create a key to use...
            var keyId = await _cryptographyService.CreateAsymmetricKey(CryptographyServiceReference);
            var data = "this is some text";
            var dataBytes = System.Text.Encoding.UTF8.GetBytes(data);

            var signature = await _cryptographyService.SignData(CryptographyServiceReference, keyId, dataBytes);
            var isValid = await _cryptographyService.VerifyData(CryptographyServiceReference, keyId, dataBytes, signature);

            Assert.IsTrue(isValid);
        }

        [TestMethod]
        public async Task AsymmetricCryptographyTest_EncryptData01()
        {
            // create a key to use...
            var customerKey = await _cryptographyService.CreateAsymmetricKey(CryptographyServiceReference);
            var serverKey = await _cryptographyService.CreateAsymmetricKey(CryptographyServiceReference);

            var data = "this is some text";
            var dataBytes = System.Text.Encoding.UTF8.GetBytes(data);

            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(CryptographyServiceReference).SingleOrDefault()
                ?? throw new Exception("Missing key connector.");
            var customerPublicKey = await _keyProvider.GetAsymmetricKey(keyConnector, customerKey);
            var serverPublicKey = await _keyProvider.GetAsymmetricKey(keyConnector, serverKey);

            var encrypted = await _cryptographyService.EncryptData(CryptographyServiceReference, serverKey, dataBytes, customerPublicKey.PublicKey);
            var decrypted = await _cryptographyService.DecryptData(CryptographyServiceReference, customerKey, encrypted, serverPublicKey.PublicKey);
            var decryptedString = System.Text.Encoding.UTF8.GetString(decrypted);

            Assert.AreEqual(data, decryptedString);
        }

        [TestMethod]
        public async Task AsymmetricCryptographyTest_SignEntity01()
        {
            // create a key to use...
            var keyId = await _cryptographyService.CreateAsymmetricKey(CryptographyServiceReference);
            var data = new TestSignedEntity()
            {
                TestField = "SomeTestValue"
            };

            var signed = await _cryptographyService.SignEntity(CryptographyServiceReference, keyId, data);
            var isValid = await _cryptographyService.VerifyEntity(CryptographyServiceReference, keyId, signed);

            Assert.IsTrue(isValid);
        }

        [TestMethod]
        public async Task AsymmetricCryptographyTest_SignEntity02()
        {
            // create a key to use...
            var keyId = await _cryptographyService.CreateAsymmetricKey(CryptographyServiceReference);

            var newKey = await _cryptographyService.GetAsymmetricKey(CryptographyServiceReference, keyId);
            newKey.Id = Guid.NewGuid();

            var newKeyId = await _cryptographyService.ImportAsymmetricKey(CryptographyServiceReference, newKey);

            var data = new TestSignedEntity()
            {
                TestField = "SomeTestValue"
            };

            var signed = await _cryptographyService.SignEntity(CryptographyServiceReference, keyId, data);
            var isValid = await _cryptographyService.VerifyEntity(CryptographyServiceReference, newKeyId, signed);

            Assert.IsTrue(isValid);
        }

        [TestMethod]
        public async Task AsymmetricCryptographyTest_EncryptEntity01()
        {
            // create a key to use...
            var customerKey = await _cryptographyService.CreateAsymmetricKey(CryptographyServiceReference);
            var serverKey = await _cryptographyService.CreateAsymmetricKey(CryptographyServiceReference);

            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(CryptographyServiceReference).SingleOrDefault()
                ?? throw new Exception("Missing key connector.");
            var customerPublicKey = await _keyProvider.GetAsymmetricKey(keyConnector, customerKey);
            var serverPublicKey = await _keyProvider.GetAsymmetricKey(keyConnector, serverKey);

            var data = new TestSignedEntity()
            {
                TestField = "SomeTestValue"
            };

            // customer calls a server API providing public key, server is encrypting the entity before returning it... server also returns its
            //  public key / customer already has trusted public key
            var encrypted = await _cryptographyService.EncryptEntity(CryptographyServiceReference, serverKey, data, customerPublicKey.PublicKey);

            // customer receives encrypted data back from server, decrypts it using customer's public/private key and server's public key...
            var decrypted = await _cryptographyService.DecryptEntity(CryptographyServiceReference, customerKey, encrypted, serverPublicKey.PublicKey);

            Assert.AreEqual(data.TestField, decrypted.TestField);
        }
    }
}