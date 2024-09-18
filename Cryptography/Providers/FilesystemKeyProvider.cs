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

#endregion

namespace Sidub.Platform.Cryptography.Providers
{

    /// <summary>
    /// Represents a provider for managing cryptographic keys stored in the filesystem.
    /// </summary>
    public class FilesystemKeyProvider : CryptographyProviderBase
    {

        #region Member variables

        private readonly IEntitySerializerService _serializerService;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="FilesystemKeyProvider"/> class.
        /// </summary>
        /// <param name="serializerService">The entity serializer service.</param>
        public FilesystemKeyProvider(IEntitySerializerService serializerService) : base(serializerService)
        {
            _serializerService = serializerService;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Creates a new symmetric key and stores it in the filesystem.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <returns>The descriptor of the created symmetric key.</returns>
        public override async Task<KeyDescriptor> CreateSymmetricKey(IKeyConnector keyConnector)
        {
            if (keyConnector is not FilesystemKeyConnector fsKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            var keyId = Guid.NewGuid();
            using var aes = CryptographyProviderHelper.GetAesProvider();
            var key = new SymmetricKey(keyId, aes.Key);

            using var fileStream = new FileStream(@$"{fsKeyConnector.KeyPath}\{keyId}.key", FileMode.Create);

            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            var data = _serializerService.Serialize(key, serializerOptions);

            await fileStream.WriteAsync(data, 0, data.Length);

            var result = new KeyDescriptor(keyId);

            return result;
        }

        /// <summary>
        /// Retrieves a symmetric key from the filesystem.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The descriptor of the symmetric key.</param>
        /// <returns>The retrieved symmetric key.</returns>
        public override Task<SymmetricKey> GetSymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor)
        {
            if (keyConnector is not FilesystemKeyConnector fsKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            using var fileStream = new FileStream(@$"{fsKeyConnector.KeyPath}\{keyDescriptor.Id}.key", FileMode.Open);
            using var memoryStream = new MemoryStream();
            fileStream.CopyTo(memoryStream);

            var data = memoryStream.ToArray();
            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            var key = _serializerService.Deserialize<SymmetricKey>(data, serializerOptions);

            return Task.FromResult(key);
        }

        /// <summary>
        /// Creates a new asymmetric key pair and stores it in the filesystem.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <returns>The descriptor of the created asymmetric key pair.</returns>
        public override async Task<KeyDescriptor> CreateAsymmetricKey(IKeyConnector keyConnector)
        {
            if (keyConnector is not FilesystemKeyConnector fsKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            var keyId = Guid.NewGuid();
            using var ecdsa = CryptographyProviderHelper.GetECDsaProvider();

            var publicKeyData = ecdsa.ExportSubjectPublicKeyInfo();
            var privateKeyData = ecdsa.ExportPkcs8PrivateKey();

            var key = new AsymmetricKey(keyId, publicKeyData, privateKeyData);

            using var fileStream = new FileStream(@$"{fsKeyConnector.KeyPath}\{keyId}.key", FileMode.Create);

            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            var data = _serializerService.Serialize(key, serializerOptions);

            await fileStream.WriteAsync(data, 0, data.Length);

            var result = new KeyDescriptor(keyId);

            return result;
        }

        /// <summary>
        /// Retrieves an asymmetric key pair from the filesystem.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The descriptor of the asymmetric key pair.</param>
        /// <param name="exportPrivate">A flag indicating whether to export the private key.</param>
        /// <returns>The retrieved asymmetric key pair.</returns>
        public override async Task<AsymmetricKey> GetAsymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, bool exportPrivate = false)
        {
            if (keyConnector is not FilesystemKeyConnector fsKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            using var fileStream = new FileStream(@$"{fsKeyConnector.KeyPath}\{keyDescriptor.Id}.key", FileMode.Open);
            using var memoryStream = new MemoryStream();
            await fileStream.CopyToAsync(memoryStream);

            var data = memoryStream.ToArray();
            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            var key = _serializerService.Deserialize<AsymmetricKey>(data, serializerOptions);

            if (!exportPrivate)
                key.PrivateKey = null;

            return key;
        }

        /// <summary>
        /// Determines whether the specified key connector is supported by this provider.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <returns><c>true</c> if the key connector is supported; otherwise, <c>false</c>.</returns>
        public override bool IsHandled(IKeyConnector keyConnector)
        {
            return keyConnector is IKeyConnector<FilesystemKeyProvider>;
        }

        /// <summary>
        /// Imports a symmetric key and stores it in the filesystem.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="key">The symmetric key to import.</param>
        /// <returns>The descriptor of the imported symmetric key.</returns>
        public override async Task<KeyDescriptor> ImportSymmetricKey(IKeyConnector keyConnector, SymmetricKey key)
        {
            if (keyConnector is not FilesystemKeyConnector fsKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            var descriptor = new KeyDescriptor(key.Id, key.Version);

            using var fileStream = new FileStream(@$"{fsKeyConnector.KeyPath}\{key.Id}.key", FileMode.Create);

            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            var data = _serializerService.Serialize(key, serializerOptions);

            await fileStream.WriteAsync(data, 0, data.Length);

            return descriptor;
        }

        /// <summary>
        /// Imports an asymmetric key pair and stores it in the filesystem.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="key">The asymmetric key pair to import.</param>
        /// <returns>The descriptor of the imported asymmetric key pair.</returns>
        public override async Task<KeyDescriptor> ImportAsymmetricKey(IKeyConnector keyConnector, AsymmetricKey key)
        {
            if (keyConnector is not FilesystemKeyConnector fsKeyConnector)
                throw new Exception($"The provided key connector type '{keyConnector.GetType().Name}' is not supported.");

            var descriptor = new KeyDescriptor(key.Id, key.Version);

            using var fileStream = new FileStream(@$"{fsKeyConnector.KeyPath}\{key.Id}.key", FileMode.Create);

            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            var data = _serializerService.Serialize(key, serializerOptions);

            await fileStream.WriteAsync(data, 0, data.Length);

            return descriptor;
        }

        #endregion

    }
}
