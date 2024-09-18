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
using Sidub.Platform.Core.Services;
using Sidub.Platform.Cryptography.Connectors;
using Sidub.Platform.Cryptography.Providers;

#endregion

namespace Sidub.Platform.Cryptography.Services
{

    /// <summary>
    /// Service for performing cryptographic operations.
    /// </summary>
    public class CryptographyService : ICryptographyService
    {

        #region Member variables

        private readonly List<ICryptographyProvider> _cryptographyProviders;
        private readonly IServiceRegistry _serviceRegistry;
        private readonly IEntitySerializerService _serializerService;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographyService"/> class.
        /// </summary>
        /// <param name="serviceRegistry">The metadata service.</param>
        /// <param name="serializerService">The serializer service.</param>
        /// <param name="keyProviders">The cryptography providers.</param>
        public CryptographyService(IServiceRegistry serviceRegistry, IEntitySerializerService serializerService, IEnumerable<ICryptographyProvider> keyProviders)
        {
            _serviceRegistry = serviceRegistry;
            _serializerService = serializerService;
            _cryptographyProviders = keyProviders.ToList();
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Gets the cryptography provider based on the specified context.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <returns>The cryptography provider.</returns>
        public ICryptographyProvider GetProvider(CryptographyServiceReference context)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            foreach (var keyProvider in _cryptographyProviders)
            {
                if (keyProvider.IsHandled(keyConnector))
                    return keyProvider;
            }

            throw new Exception($"Key provider not found for key provider type '{keyConnector.GetType().Name}'.");
        }

        /// <summary>
        /// Creates an asymmetric key based on the specified context.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <returns>The created key descriptor.</returns>
        public Task<KeyDescriptor> CreateAsymmetricKey(CryptographyServiceReference context)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.CreateAsymmetricKey(keyConnector);

            return result;
        }

        /// <summary>
        /// Creates a symmetric key based on the specified context.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <returns>The created key descriptor.</returns>
        public Task<KeyDescriptor> CreateSymmetricKey(CryptographyServiceReference context)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.CreateSymmetricKey(keyConnector);

            return result;
        }

        /// <summary>
        /// Decrypts the specified symmetric data using the provided key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The symmetric data to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        public Task<byte[]> DecryptData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, SymmetricData data)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.DecryptData(keyConnector, keyDescriptor, data);

            return result;
        }

        /// <summary>
        /// Decrypts the specified symmetric data using the provided key descriptor and public key.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The symmetric data to decrypt.</param>
        /// <param name="publicKey">The public key used for decryption.</param>
        /// <returns>The decrypted data.</returns>
        public Task<byte[]> DecryptData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, SymmetricData data, byte[] publicKey)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.DecryptData(keyConnector, keyDescriptor, data, publicKey);

            return result;
        }

        /// <summary>
        /// Decrypts the specified symmetric entity using the provided key descriptor.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="symmetricEntity">The symmetric entity to decrypt.</param>
        /// <returns>The decrypted entity.</returns>
        public Task<TEntity> DecryptEntity<TEntity>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, SymmetricEntity<TEntity> symmetricEntity) where TEntity : IEntity
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.DecryptEntity(keyConnector, keyDescriptor, symmetricEntity);

            return result;
        }

        /// <summary>
        /// Decrypts the specified symmetric entity using the provided key descriptor and public key.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="symmetricEntity">The symmetric entity to decrypt.</param>
        /// <param name="publicKey">The public key used for decryption.</param>
        /// <returns>The decrypted entity.</returns>
        public Task<TEntity> DecryptEntity<TEntity>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, SymmetricEntity<TEntity> symmetricEntity, byte[] publicKey) where TEntity : IEntity
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.DecryptEntity(keyConnector, keyDescriptor, symmetricEntity, publicKey);

            return result;
        }

        /// <summary>
        /// Encrypts the specified data using the provided key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        public Task<SymmetricData> EncryptData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, byte[] data)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.EncryptData(keyConnector, keyDescriptor, data);

            return result;
        }

        /// <summary>
        /// Encrypts the specified data using the provided key descriptor and public key.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="publicKey">The public key used for encryption.</param>
        /// <returns>The encrypted data.</returns>
        public Task<SymmetricData> EncryptData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, byte[] data, byte[] publicKey)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.EncryptData(keyConnector, keyDescriptor, data, publicKey);

            return result;
        }

        /// <summary>
        /// Encrypts the specified entity using the provided key descriptor.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="entity">The entity to encrypt.</param>
        /// <returns>The encrypted entity.</returns>
        public Task<SymmetricEntity<TEntity>> EncryptEntity<TEntity>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, TEntity entity) where TEntity : IEntity
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.EncryptEntity(keyConnector, keyDescriptor, entity);

            return result;
        }

        /// <summary>
        /// Encrypts the specified entity using the provided key descriptor and public key.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="entity">The entity to encrypt.</param>
        /// <param name="publicKey">The public key used for encryption.</param>
        /// <returns>The encrypted entity.</returns>
        public Task<SymmetricEntity<TEntity>> EncryptEntity<TEntity>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, TEntity entity, byte[] publicKey) where TEntity : IEntity
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.EncryptEntity(keyConnector, keyDescriptor, entity, publicKey);

            return result;
        }

        /// <summary>
        /// Signs the specified data using the provided key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The data to sign.</param>
        /// <returns>The signature.</returns>
        public Task<byte[]> SignData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, byte[] data)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.SignData(keyConnector, keyDescriptor, data);

            return result;
        }

        /// <summary>
        /// Signs the specified entity using the provided key descriptor.
        /// </summary>
        /// <typeparam name="TEntitySigned">The type of the entity.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="entity">The entity to sign.</param>
        /// <returns>The signed entity.</returns>
        public Task<TEntitySigned> SignEntity<TEntitySigned>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, TEntitySigned entity) where TEntitySigned : IEntitySigned
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.SignEntity(keyConnector, keyDescriptor, entity);

            return result;
        }

        /// <summary>
        /// Verifies the specified data using the provided key descriptor and signature.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="data">The data to verify.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>True if the data is verified, false otherwise.</returns>
        public Task<bool> VerifyData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, byte[] data, byte[] signature)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.VerifyData(keyConnector, keyDescriptor, data, signature);

            return result;
        }

        /// <summary>
        /// Verifies the specified entity using the provided key descriptor.
        /// </summary>
        /// <typeparam name="TEntitySigned">The type of the entity.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="entity">The entity to verify.</param>
        /// <returns>True if the entity is verified, false otherwise.</returns>
        public Task<bool> VerifyEntity<TEntitySigned>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, TEntitySigned entity) where TEntitySigned : IEntitySigned
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.VerifyEntity(keyConnector, keyDescriptor, entity);

            return result;
        }

        /// <summary>
        /// Gets the symmetric key based on the specified context and key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <returns>The symmetric key.</returns>
        public Task<SymmetricKey> GetSymmetricKey(CryptographyServiceReference context, KeyDescriptor keyDescriptor)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.GetSymmetricKey(keyConnector, keyDescriptor);

            return result;
        }

        /// <summary>
        /// Gets the asymmetric key based on the specified context and key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor.</param>
        /// <param name="exportPrivate">A flag indicating whether to export the private key.</param>
        /// <returns>The asymmetric key.</returns>
        public Task<AsymmetricKey> GetAsymmetricKey(CryptographyServiceReference context, KeyDescriptor keyDescriptor, bool exportPrivate = false)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.GetAsymmetricKey(keyConnector, keyDescriptor, exportPrivate);

            return result;
        }

        /// <summary>
        /// Imports the symmetric key into the specified context.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="key">The symmetric key to import.</param>
        /// <returns>The imported key descriptor.</returns>
        public Task<KeyDescriptor> ImportSymmetricKey(CryptographyServiceReference context, SymmetricKey key)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.ImportSymmetricKey(keyConnector, key);

            return result;
        }

        /// <summary>
        /// Imports the asymmetric key into the specified context.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="key">The asymmetric key to import.</param>
        /// <returns>The imported key descriptor.</returns>
        public Task<KeyDescriptor> ImportAsymmetricKey(CryptographyServiceReference context, AsymmetricKey key)
        {
            var keyConnector = _serviceRegistry.GetMetadata<IKeyConnector>(context).SingleOrDefault()
                ?? throw new Exception($"An IKeyConnector could not be found for cryptography service context '{context.Name}'.");

            var provider = GetProvider(context);
            var result = provider.ImportAsymmetricKey(keyConnector, key);

            return result;
        }

        #endregion

    }

}
