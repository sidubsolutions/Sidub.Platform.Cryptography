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

using Sidub.Platform.Core.Entity;
using Sidub.Platform.Core.Extensions;
using Sidub.Platform.Core.Serializers;
using Sidub.Platform.Core.Services;
using Sidub.Platform.Cryptography.Connectors;
using System.Security.Cryptography;

#endregion

namespace Sidub.Platform.Cryptography.Providers
{

    /// <summary>
    /// Base class for cryptography providers.
    /// </summary>
    public abstract class CryptographyProviderBase : ICryptographyProvider
    {

        #region Member variables

        private readonly IEntitySerializerService _serializerService;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographyProviderBase"/> class.
        /// </summary>
        /// <param name="serializerService">The entity serializer service.</param>
        public CryptographyProviderBase(IEntitySerializerService serializerService)
        {
            _serializerService = serializerService;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Determines whether the specified key connector is handled by this provider.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <returns><c>true</c> if the key connector is handled; otherwise, <c>false</c>.</returns>
        public abstract bool IsHandled(IKeyConnector keyConnector);

        /// <summary>
        /// Imports a symmetric key using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="key">The symmetric key to import.</param>
        /// <returns>The imported key descriptor.</returns>
        public abstract Task<KeyDescriptor> ImportSymmetricKey(IKeyConnector keyConnector, SymmetricKey key);

        /// <summary>
        /// Creates a new symmetric key using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <returns>The created key descriptor.</returns>
        public abstract Task<KeyDescriptor> CreateSymmetricKey(IKeyConnector keyConnector);

        /// <summary>
        /// Gets the symmetric key using the specified key connector and key descriptor.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <returns>The symmetric key.</returns>
        public abstract Task<SymmetricKey> GetSymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor);

        /// <summary>
        /// Imports an asymmetric key using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="key">The asymmetric key to import.</param>
        /// <returns>The imported key descriptor.</returns>
        public abstract Task<KeyDescriptor> ImportAsymmetricKey(IKeyConnector keyConnector, AsymmetricKey key);

        /// <summary>
        /// Creates a new asymmetric key using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <returns>The created key descriptor.</returns>
        public abstract Task<KeyDescriptor> CreateAsymmetricKey(IKeyConnector keyConnector);

        /// <summary>
        /// Gets the asymmetric key using the specified key connector and key descriptor.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="exportPrivate">Whether to export the private key.</param>
        /// <returns>The asymmetric key.</returns>
        public abstract Task<AsymmetricKey> GetAsymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, bool exportPrivate = false);

        /// <summary>
        /// Signs the specified entity using the specified key connector and key descriptor.
        /// </summary>
        /// <typeparam name="TEntitySigned">The type of the entity to sign.</typeparam>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="entity">The entity to sign.</param>
        /// <returns>The signed entity.</returns>
        public async Task<TEntitySigned> SignEntity<TEntitySigned>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, TEntitySigned entity) where TEntitySigned : IEntitySigned
        {
            var serializerOptions = SerializerOptions.New(SerializationLanguageType.Json).With(x => x.ExcludedFields.Add(SignatureEntityField.Instance));
            var data = _serializerService.Serialize(entity, serializerOptions);
            var signature = await SignData(keyConnector, keyDescriptor, data);

            entity.Signature = signature;

            return entity;
        }

        /// <summary>
        /// Verifies the signature of the specified entity using the specified key connector and key descriptor.
        /// </summary>
        /// <typeparam name="TEntitySigned">The type of the entity to verify.</typeparam>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="entity">The entity to verify.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public async Task<bool> VerifyEntity<TEntitySigned>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, TEntitySigned entity) where TEntitySigned : IEntitySigned
        {
            if (entity.Signature is null)
                throw new Exception("No signature exists.");

            bool isValid = false;
            var signature = entity.Signature;

            var serializerOptions = SerializerOptions.New(SerializationLanguageType.Json).With(x => x.ExcludedFields.Add(SignatureEntityField.Instance));
            var data = _serializerService.Serialize(entity, serializerOptions);
            isValid = await VerifyData(keyConnector, keyDescriptor, data, signature);

            return isValid;
        }

        /// <summary>
        /// Signs the specified data using the specified key connector and key descriptor.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The data to sign.</param>
        /// <returns>The signature of the data.</returns>
        public async Task<byte[]> SignData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, byte[] data)
        {
            var key = await GetAsymmetricKey(keyConnector, keyDescriptor, true);

            if (!key.IsPrivateKey)
                throw new Exception("Provided key does not contain private portion; it cannot be used for signing data.");

            using var ecdsa = CryptographyProviderHelper.GetECDsaProvider(key);
            var result = ecdsa.SignData(data, HashAlgorithmName.SHA256);

            return result;
        }

        /// <summary>
        /// Verifies the signature of the specified data using the specified key connector, key descriptor, data, and signature.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The data to verify.</param>
        /// <param name="signature">The signature of the data.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public async Task<bool> VerifyData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, byte[] data, byte[] signature)
        {
            var key = await GetAsymmetricKey(keyConnector, keyDescriptor);
            using var ecdsa = CryptographyProviderHelper.GetECDsaProvider(key);

            var result = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
            return result;
        }

        /// <summary>
        /// Encrypts the specified data using the specified key connector and key descriptor.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        public async Task<SymmetricData> EncryptData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, byte[] data)
        {
            var key = await GetSymmetricKey(keyConnector, keyDescriptor);

            using var provider = CryptographyProviderHelper.GetAesProvider(key);

            byte[] encryptedData;

            using (var encryptor = provider.CreateEncryptor())
            {
                using var ms = new MemoryStream();
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }

                encryptedData = ms.ToArray();
            }

            var symmetricData = new SymmetricData()
            {
                InitializationVector = provider.IV,
                CipherText = encryptedData
            };
            return symmetricData;
        }

        /// <summary>
        /// Decrypts the specified data using the specified key connector and key descriptor.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The data to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        public async Task<byte[]> DecryptData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, SymmetricData data)
        {
            var key = await GetSymmetricKey(keyConnector, keyDescriptor);

            using var provider = CryptographyProviderHelper.GetAesProvider();
            provider.Key = key.Key;
            provider.IV = data.InitializationVector;

            using var targetStream = new MemoryStream();

            var readBlockSize = provider.BlockSize / 8;

            using (var decryptor = provider.CreateDecryptor())
            {
                using var ms = new MemoryStream(data.CipherText);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

                var readBlockOffset = 0;
                var readBlockCount = 0;
                byte[] decryptedBlock = new byte[readBlockSize];

                // iterate until the retrieved block count is not equal to the requested block count... this means we've retrieved
                //  less than requested and we're at the end of the stream...
                do
                {
                    readBlockCount = cs.Read(decryptedBlock, readBlockOffset, readBlockSize);
                    await targetStream.WriteAsync(decryptedBlock, readBlockOffset, readBlockCount);
                    await targetStream.FlushAsync();
                }
                while (readBlockCount == readBlockSize);
            }

            var decrypted = targetStream.ToArray();

            return decrypted;
        }

        /// <summary>
        /// Encrypts the specified entity using the specified key connector and key descriptor.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to encrypt.</typeparam>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="entity">The entity to encrypt.</param>
        /// <returns>The encrypted entity.</returns>
        public async Task<SymmetricEntity<TEntity>> EncryptEntity<TEntity>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, TEntity entity) where TEntity : IEntity
        {
            SymmetricEntity<TEntity> result;

            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            var data = _serializerService.Serialize(entity, serializerOptions);

            var encryptedData = await EncryptData(keyConnector, keyDescriptor, data);

            result = SymmetricEntity<TEntity>.CreateFromSymmetricData(encryptedData);

            return result;
        }

        /// <summary>
        /// Decrypts the specified entity using the specified key connector and key descriptor.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to decrypt.</typeparam>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="symmetricEntity">The symmetric entity to decrypt.</param>
        /// <returns>The decrypted entity.</returns>
        public async Task<TEntity> DecryptEntity<TEntity>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, SymmetricEntity<TEntity> symmetricEntity) where TEntity : IEntity
        {
            TEntity result;

            var decryptedData = await DecryptData(keyConnector, keyDescriptor, symmetricEntity);

            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            result = _serializerService.Deserialize<TEntity>(decryptedData, serializerOptions);

            return result;
        }

        /// <summary>
        /// Encrypts the specified entity using the specified key connector, key descriptor, and public key bytes.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to encrypt.</typeparam>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="entity">The entity to encrypt.</param>
        /// <param name="publicKeyBytes">The public key bytes.</param>
        /// <returns>The encrypted entity.</returns>
        public async Task<SymmetricEntity<TEntity>> EncryptEntity<TEntity>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, TEntity entity, byte[] publicKeyBytes) where TEntity : IEntity
        {
            SymmetricEntity<TEntity> result;

            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            var data = _serializerService.Serialize(entity, serializerOptions);

            var encryptedData = await EncryptData(keyConnector, keyDescriptor, data, publicKeyBytes);

            result = SymmetricEntity<TEntity>.CreateFromSymmetricData(encryptedData);

            return result;
        }

        /// <summary>
        /// Decrypts the specified entity using the specified key connector, key descriptor, and public key bytes.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to decrypt.</typeparam>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="symmetricEntity">The symmetric entity to decrypt.</param>
        /// <param name="publicKeyBytes">The public key bytes.</param>
        /// <returns>The decrypted entity.</returns>
        public async Task<TEntity> DecryptEntity<TEntity>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, SymmetricEntity<TEntity> symmetricEntity, byte[] publicKeyBytes) where TEntity : IEntity
        {
            TEntity result;

            var decryptedData = await DecryptData(keyConnector, keyDescriptor, symmetricEntity, publicKeyBytes);

            var serializerOptions = SerializerOptions.Default(SerializationLanguageType.Json);
            result = _serializerService.Deserialize<TEntity>(decryptedData, serializerOptions);
            return result;
        }

        /// <summary>
        /// Encrypts the specified data using the specified key connector, key descriptor, and public key bytes. Leverages key agreement protocol
        /// to derive a symmetric key based on the sender's asymmetric key and the recipient's asymmetric public key.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The sender's key descriptor.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="publicKeyBytes">The recipient's public key bytes.</param>
        /// <returns>The encrypted data.</returns>
        public async Task<SymmetricData> EncryptData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, byte[] data, byte[] publicKeyBytes)
        {
            var key = await GetAsymmetricKey(keyConnector, keyDescriptor, true);
            using var ecdh = CryptographyProviderHelper.GetECDiffieHellmanProvider(key);

            using var publicEcdh = CryptographyProviderHelper.GetECDiffieHellmanProvider();
            publicEcdh.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            using var publicKey = publicEcdh.PublicKey;
            var symmetricKeyBytes = ecdh.DeriveKeyFromHash(publicKey, HashAlgorithmName.SHA256);

            using var provider = CryptographyProviderHelper.GetAesProvider();
            provider.Key = symmetricKeyBytes;

            byte[] encryptedData;

            using (var encryptor = provider.CreateEncryptor())
            {
                using var ms = new MemoryStream();
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }

                encryptedData = ms.ToArray();
            }

            var symmetricData = new SymmetricData()
            {
                InitializationVector = provider.IV,
                CipherText = encryptedData
            };

            return symmetricData;
        }

        /// <summary>
        /// Decrypts the specified data using the specified key connector, key descriptor, and public key bytes. Leverages key agreement protocol
        /// to derive a symmetric key based on the sender's asymmetric key and the recipient's asymmetric public key.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The sender's key descriptor.</param>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="publicKeyBytes">The recipient's public key bytes.</param>
        /// <returns>The decrypted data.</returns>
        public async Task<byte[]> DecryptData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, SymmetricData data, byte[] publicKeyBytes)
        {
            var key = await GetAsymmetricKey(keyConnector, keyDescriptor, true);
            using var ecdh = CryptographyProviderHelper.GetECDiffieHellmanProvider(key);

            using var publicEcdh = CryptographyProviderHelper.GetECDiffieHellmanProvider();
            publicEcdh.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            using var publicKey = publicEcdh.PublicKey;
            var symmetricKeyBytes = ecdh.DeriveKeyFromHash(publicKey, HashAlgorithmName.SHA256);

            using var provider = CryptographyProviderHelper.GetAesProvider();
            provider.Key = symmetricKeyBytes;
            provider.IV = data.InitializationVector;

            using var targetStream = new MemoryStream();

            var readBlockSize = provider.BlockSize / 8;

            using (var decryptor = provider.CreateDecryptor())
            {
                using var ms = new MemoryStream(data.CipherText);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

                var readBlockOffset = 0;
                var readBlockCount = 0;
                byte[] decryptedBlock = new byte[readBlockSize];

                // iterate until the retrieved block count and write the data...
                do
                {
                    readBlockCount = cs.Read(decryptedBlock, readBlockOffset, readBlockSize);
                    await targetStream.WriteAsync(decryptedBlock, readBlockOffset, readBlockCount);
                    await targetStream.FlushAsync();
                }
                while (readBlockCount == readBlockSize);
            }

            var decrypted = targetStream.ToArray();

            return decrypted;
        }

        #endregion

    }

}
