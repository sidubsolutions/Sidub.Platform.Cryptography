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
using Sidub.Platform.Cryptography.Providers;

#endregion

namespace Sidub.Platform.Cryptography.Services
{

    /// <summary>
    /// Represents a cryptography service that provides various cryptographic operations.
    /// </summary>
    public interface ICryptographyService
    {

        #region Interface methods

        /// <summary>
        /// Gets the cryptography provider based on the specified cryptography service reference.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <returns>The cryptography provider.</returns>
        ICryptographyProvider GetProvider(CryptographyServiceReference context);

        /// <summary>
        /// Imports a symmetric key into the cryptography service.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="key">The symmetric key to import.</param>
        /// <returns>The key descriptor of the imported symmetric key.</returns>
        Task<KeyDescriptor> ImportSymmetricKey(CryptographyServiceReference context, SymmetricKey key);

        /// <summary>
        /// Creates a new symmetric key in the cryptography service.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <returns>The key descriptor of the created symmetric key.</returns>
        Task<KeyDescriptor> CreateSymmetricKey(CryptographyServiceReference context);

        /// <summary>
        /// Gets the symmetric key from the cryptography service based on the specified key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the symmetric key.</param>
        /// <returns>The symmetric key.</returns>
        Task<SymmetricKey> GetSymmetricKey(CryptographyServiceReference context, KeyDescriptor keyDescriptor);

        /// <summary>
        /// Imports an asymmetric key into the cryptography service.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="key">The asymmetric key to import.</param>
        /// <returns>The key descriptor of the imported asymmetric key.</returns>
        Task<KeyDescriptor> ImportAsymmetricKey(CryptographyServiceReference context, AsymmetricKey key);

        /// <summary>
        /// Creates a new asymmetric key in the cryptography service.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <returns>The key descriptor of the created asymmetric key.</returns>
        Task<KeyDescriptor> CreateAsymmetricKey(CryptographyServiceReference context);

        /// <summary>
        /// Gets the asymmetric key from the cryptography service based on the specified key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the asymmetric key.</param>
        /// <param name="exportPrivate">A flag indicating whether to export the private key. Default is false.</param>
        /// <returns>The asymmetric key.</returns>
        Task<AsymmetricKey> GetAsymmetricKey(CryptographyServiceReference context, KeyDescriptor keyDescriptor, bool exportPrivate = false);

        /// <summary>
        /// Signs the specified data using the specified key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the signing key.</param>
        /// <param name="data">The data to sign.</param>
        /// <returns>The signature of the data.</returns>
        Task<byte[]> SignData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, byte[] data);

        /// <summary>
        /// Verifies the signature of the specified data using the specified key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the signing key.</param>
        /// <param name="data">The data to verify.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>True if the signature is valid, otherwise false.</returns>
        Task<bool> VerifyData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, byte[] data, byte[] signature);

        /// <summary>
        /// Signs the specified entity using the specified key descriptor.
        /// </summary>
        /// <typeparam name="TEntitySigned">The type of the entity to sign.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the signing key.</param>
        /// <param name="entity">The entity to sign.</param>
        /// <returns>The signed entity.</returns>
        Task<TEntitySigned> SignEntity<TEntitySigned>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, TEntitySigned entity) where TEntitySigned : IEntitySigned;

        /// <summary>
        /// Verifies the signature of the specified entity using the specified key descriptor.
        /// </summary>
        /// <typeparam name="TEntitySigned">The type of the entity to verify.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the signing key.</param>
        /// <param name="entity">The entity to verify.</param>
        /// <returns>True if the signature is valid, otherwise false.</returns>
        Task<bool> VerifyEntity<TEntitySigned>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, TEntitySigned entity) where TEntitySigned : IEntitySigned;

        /// <summary>
        /// Encrypts the specified data using the specified key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the encryption key.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        Task<SymmetricData> EncryptData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, byte[] data);

        /// <summary>
        /// Decrypts the specified data using the specified key descriptor.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the decryption key.</param>
        /// <param name="data">The data to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        Task<byte[]> DecryptData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, SymmetricData data);

        /// <summary>
        /// Encrypts the specified data using the specified key descriptor and public key.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the encryption key.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="publicKey">The public key used for encryption.</param>
        /// <returns>The encrypted data.</returns>
        Task<SymmetricData> EncryptData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, byte[] data, byte[] publicKey);

        /// <summary>
        /// Decrypts the specified data using the specified key descriptor and public key.
        /// </summary>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the decryption key.</param>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="publicKey">The public key used for decryption.</param>
        /// <returns>The decrypted data.</returns>
        Task<byte[]> DecryptData(CryptographyServiceReference context, KeyDescriptor keyDescriptor, SymmetricData data, byte[] publicKey);

        /// <summary>
        /// Encrypts the specified entity using the specified key descriptor.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to encrypt.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the encryption key.</param>
        /// <param name="entity">The entity to encrypt.</param>
        /// <returns>The encrypted entity.</returns>
        Task<SymmetricEntity<TEntity>> EncryptEntity<TEntity>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, TEntity entity) where TEntity : IEntity;

        /// <summary>
        /// Decrypts the specified entity using the specified key descriptor.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to decrypt.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the decryption key.</param>
        /// <param name="symmetricEntity">The symmetric entity to decrypt.</param>
        /// <returns>The decrypted entity.</returns>
        Task<TEntity> DecryptEntity<TEntity>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, SymmetricEntity<TEntity> symmetricEntity) where TEntity : IEntity;

        /// <summary>
        /// Encrypts the specified entity using the specified key descriptor and public key.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to encrypt.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the encryption key.</param>
        /// <param name="entity">The entity to encrypt.</param>
        /// <param name="publicKey">The public key used for encryption.</param>
        /// <returns>The encrypted entity.</returns>
        Task<SymmetricEntity<TEntity>> EncryptEntity<TEntity>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, TEntity entity, byte[] publicKey) where TEntity : IEntity;

        /// <summary>
        /// Decrypts the specified entity using the specified key descriptor and public key.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to decrypt.</typeparam>
        /// <param name="context">The cryptography service reference.</param>
        /// <param name="keyDescriptor">The key descriptor of the decryption key.</param>
        /// <param name="symmetricEntity">The symmetric entity to decrypt.</param>
        /// <param name="publicKey">The public key used for decryption.</param>
        /// <returns>The decrypted entity.</returns>
        Task<TEntity> DecryptEntity<TEntity>(CryptographyServiceReference context, KeyDescriptor keyDescriptor, SymmetricEntity<TEntity> symmetricEntity, byte[] publicKey) where TEntity : IEntity;

        #endregion

    }

}
