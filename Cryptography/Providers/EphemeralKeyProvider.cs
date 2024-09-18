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

using Sidub.Platform.Core.Serializers;
using Sidub.Platform.Core.Services;
using Sidub.Platform.Cryptography.Connectors;
using System.Collections.Concurrent;

#endregion

namespace Sidub.Platform.Cryptography.Providers
{

    /// <summary>
    /// Provides an implementation of the <see cref="CryptographyProviderBase"/> for ephemeral key management.
    /// </summary>
    public class EphemeralKeyProvider : CryptographyProviderBase
    {

        #region Member variables

        private readonly IEntitySerializerService _serializerService;
        private readonly ConcurrentDictionary<Guid, byte[]> _keyStore;
        private readonly IEntitySerializerOptions _serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);

        private volatile bool _isInitialized = false;
        private SemaphoreSlim _initializationLock = new SemaphoreSlim(1, 1);

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="EphemeralKeyProvider"/> class.
        /// </summary>
        /// <param name="serializerService">The entity serializer service.</param>
        public EphemeralKeyProvider(IEntitySerializerService serializerService) : base(serializerService)
        {
            _serializerService = serializerService;
            _keyStore = new ConcurrentDictionary<Guid, byte[]>();
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Determines whether the specified key connector is handled by this provider.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <returns><c>true</c> if the key connector is handled by this provider; otherwise, <c>false</c>.</returns>
        public override bool IsHandled(IKeyConnector keyConnector)
        {
            return keyConnector is IKeyConnector<EphemeralKeyProvider>;
        }

        /// <summary>
        /// Creates a new symmetric key using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the created key descriptor.</returns>
        public override async Task<KeyDescriptor> CreateSymmetricKey(IKeyConnector keyConnector)
        {
            if (keyConnector is not EphemeralKeyConnector ephKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            await CheckInitialized(ephKeyConnector);

            var keyId = Guid.NewGuid();
            using var aes = CryptographyProviderHelper.GetAesProvider();
            var key = new SymmetricKey(keyId, aes.Key);

            var data = _serializerService.Serialize(key, _serializerOptions);

            if (!_keyStore.TryAdd(keyId, data))
                throw new Exception($"Could not add key with id '{keyId}' to key store.");

            var result = new KeyDescriptor(keyId);

            return result;
        }

        /// <summary>
        /// Retrieves the symmetric key with the specified key descriptor using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the retrieved symmetric key.</returns>
        public override async Task<SymmetricKey> GetSymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor)
        {
            if (keyConnector is not EphemeralKeyConnector ephKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            await CheckInitialized(ephKeyConnector);

            var data = _keyStore[keyDescriptor.Id];
            var key = _serializerService.Deserialize<SymmetricKey>(data, _serializerOptions);

            return key;
        }

        /// <summary>
        /// Creates a new asymmetric key pair using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the created key descriptor.</returns>
        public override async Task<KeyDescriptor> CreateAsymmetricKey(IKeyConnector keyConnector)
        {
            if (keyConnector is not EphemeralKeyConnector ephKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            await CheckInitialized(ephKeyConnector);

            var keyId = Guid.NewGuid();
            using var ecdsa = CryptographyProviderHelper.GetECDsaProvider();

            var publicKeyData = ecdsa.ExportSubjectPublicKeyInfo();
            var privateKeyData = ecdsa.ExportPkcs8PrivateKey();

            var key = new AsymmetricKey(keyId, publicKeyData, privateKeyData);
            var data = _serializerService.Serialize(key, _serializerOptions);

            if (!_keyStore.TryAdd(keyId, data))
                throw new Exception($"Could not add key with id '{keyId}' to key store.");

            var result = new KeyDescriptor(keyId);

            return result;
        }

        /// <summary>
        /// Retrieves the asymmetric key with the specified key descriptor using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="exportPrivate">A flag indicating whether to export the private key.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the retrieved asymmetric key.</returns>
        public override async Task<AsymmetricKey> GetAsymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, bool exportPrivate = false)
        {
            if (keyConnector is not EphemeralKeyConnector ephKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            await CheckInitialized(ephKeyConnector);

            var data = _keyStore[keyDescriptor.Id];
            var key = _serializerService.Deserialize<AsymmetricKey>(data, _serializerOptions);

            if (!exportPrivate)
                key.PrivateKey = null;

            return key;
        }

        /// <summary>
        /// Imports a symmetric key using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="key">The symmetric key to import.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the imported key descriptor.</returns>
        public override async Task<KeyDescriptor> ImportSymmetricKey(IKeyConnector keyConnector, SymmetricKey key)
        {
            if (keyConnector is not EphemeralKeyConnector ephKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            await CheckInitialized(ephKeyConnector);

            if (_keyStore.ContainsKey(key.Id))
                throw new Exception($"Cannot import key as key id '{key.Id}' already exists.");

            var descriptor = new KeyDescriptor(key.Id, key.Version);

            var data = _serializerService.Serialize(key, _serializerOptions);

            if (!_keyStore.TryAdd(key.Id, data))
                throw new Exception($"Could not add key with id '{key.Id}' to key store.");

            return descriptor;
        }

        /// <summary>
        /// Imports an asymmetric key pair using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="key">The asymmetric key pair to import.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the imported key descriptor.</returns>
        public override async Task<KeyDescriptor> ImportAsymmetricKey(IKeyConnector keyConnector, AsymmetricKey key)
        {
            if (keyConnector is not EphemeralKeyConnector ephKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            await CheckInitialized(ephKeyConnector);

            if (_keyStore.ContainsKey(key.Id))
                throw new Exception($"Cannot import key as key id '{key.Id}' already exists.");

            var descriptor = new KeyDescriptor(key.Id, key.Version);

            var data = _serializerService.Serialize(key, _serializerOptions);

            if (!_keyStore.TryAdd(key.Id, data))
                throw new Exception($"Could not add key with id '{key.Id}' to key store.");

            return descriptor;
        }

        #endregion

        #region Private methods

        /// <summary>
        /// Checks if the EphemeralKeyProvider is initialized and initializes it if necessary.
        /// </summary>
        /// <param name="ephKeyConnector">The EphemeralKeyConnector instance.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task CheckInitialized(EphemeralKeyConnector ephKeyConnector)
        {
            if (!_isInitialized)
            {
                await _initializationLock.WaitAsync();

                try
                {
                    if (!_isInitialized)
                    {
                        foreach (var symKey in ephKeyConnector.SymmetricKeys)
                        {
                            var serializedKey = _serializerService.Serialize(symKey, _serializerOptions);
                            if (!_keyStore.TryAdd(symKey.Id, serializedKey))
                                throw new Exception($"Could not add key with id '{symKey.Id}' to key store.");
                        }

                        foreach (var asymKey in ephKeyConnector.AsymmetricKeys)
                        {
                            var serializedKey = _serializerService.Serialize(asymKey, _serializerOptions);
                            if (!_keyStore.TryAdd(asymKey.Id, serializedKey))
                                throw new Exception($"Could not add key with id '{asymKey.Id}' to key store.");
                        }

                        _isInitialized = true;
                    }
                }
                finally
                {
                    _initializationLock.Release();
                }
            }
        }

        #endregion

    }

}
