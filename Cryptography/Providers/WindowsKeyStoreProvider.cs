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

//using Sidub.Platform.Core.Serializers;
//using Sidub.Platform.Core.Services;
//using Sidub.Platform.Cryptography.Connectors;
//using System.Runtime.InteropServices;
//using System.Security.Cryptography;

//namespace Sidub.Platform.Cryptography.Providers
//{
//    public class WindowsKeyStoreProvider : CryptographyProviderBase
//    {

//        private readonly IEntitySerializerService _serializerService;
//        //private readonly Dictionary<Guid, byte[]> _keyStore;

//        public WindowsKeyStoreProvider(IEntitySerializerService serializerService) : base(serializerService)
//        {
//            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
//                throw new Exception("Windows Key Store Provider is only supported on Windows.");

//            _serializerService = serializerService;
//            //_keyStore = new Dictionary<Guid, byte[]>();
//        }

//        public override Task<KeyDescriptor> CreateSymmetricKey(IKeyConnector keyConnector)
//        {
//            var keyId = Guid.NewGuid();
//            using var aes = CryptographyProviderHelper.GetAesProvider();
//            var key = new SymmetricKey(keyId, aes.Key);

//            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
//            var data = _serializerService.Serialize(key, serializerOptions);

//            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
//                throw new Exception("Windows Key Store Provider is only supported on Windows.");

//            var keyImport = CngKey.Import(data, CngKeyBlobFormat.GenericPrivateBlob);

//            var result = new KeyDescriptor(keyId);

//            return Task.FromResult(result);
//        }

//        public override Task<SymmetricKey> GetSymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor)
//        {
//            var data = _keyStore[keyDescriptor.Id];
//            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
//            var key = _serializerService.Deserialize<SymmetricKey>(data, serializerOptions);

//            return Task.FromResult(key);
//        }

//        public override Task<KeyDescriptor> CreateAsymmetricKey(IKeyConnector keyConnector)
//        {
//            var keyId = Guid.NewGuid();
//            using var ecdsa = CryptographyProviderHelper.GetECDsaProvider();

//            var publicKeyData = ecdsa.ExportSubjectPublicKeyInfo();
//            var privateKeyData = ecdsa.ExportPkcs8PrivateKey();

//            var key = new AsymmetricKey(keyId, publicKeyData, privateKeyData);
//            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
//            var data = _serializerService.Serialize(key, serializerOptions);

//            _keyStore.Add(keyId, data);

//            var result = new KeyDescriptor(keyId);

//            return Task.FromResult(result);
//        }

//        public override Task<AsymmetricKey> GetAsymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, bool exportPrivate = false)
//        {
//            var data = _keyStore[keyDescriptor.Id];
//            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
//            var key = _serializerService.Deserialize<AsymmetricKey>(data, serializerOptions);

//            if (!exportPrivate)
//                key.PrivateKey = null;

//            return Task.FromResult(key);
//        }

//        public override bool IsHandled(IKeyConnector keyConnector)
//        {
//            return keyConnector is IKeyConnector<EphemeralKeyProvider>;
//        }

//        public override Task<KeyDescriptor> ImportSymmetricKey(IKeyConnector keyConnector, SymmetricKey key)
//        {
//            if (_keyStore.ContainsKey(key.Id))
//                throw new Exception($"Cannot import key as key id '{key.Id}' already exists.");

//            var descriptor = new KeyDescriptor(key.Id, key.Version);

//            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
//            var data = _serializerService.Serialize(key, serializerOptions);

//            _keyStore.Add(key.Id, data);

//            return Task.FromResult(descriptor);
//        }

//        public override Task<KeyDescriptor> ImportAsymmetricKey(IKeyConnector keyConnector, AsymmetricKey key)
//        {
//            if (_keyStore.ContainsKey(key.Id))
//                throw new Exception($"Cannot import key as key id '{key.Id}' already exists.");

//            var descriptor = new KeyDescriptor(key.Id, key.Version);

//            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
//            var data = _serializerService.Serialize(key, serializerOptions);

//            _keyStore.Add(key.Id, data);

//            return Task.FromResult(descriptor);
//        }

//    }
//}
