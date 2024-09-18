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
using Sidub.Platform.Cryptography.Connectors;

#endregion

namespace Sidub.Platform.Cryptography.Providers
{

    /// <summary>
    /// Represents a cryptography provider that offers various cryptographic operations.
    /// </summary>
    public interface ICryptographyProvider
    {

        #region Interface methods

        /// <summary>
        /// Determines whether the provider can handle the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector to check.</param>
        /// <returns><c>true</c> if the provider can handle the key connector; otherwise, <c>false</c>.</returns>
        bool IsHandled(IKeyConnector keyConnector);

        /// <summary>
        /// Imports a symmetric key into the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector to import the key into.</param>
        /// <param name="key">The symmetric key to import.</param>
        /// <returns>The descriptor of the imported key.</returns>
        Task<KeyDescriptor> ImportSymmetricKey(IKeyConnector keyConnector, SymmetricKey key);

        /// <summary>
        /// Creates a new symmetric key using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector to create the key with.</param>
        /// <returns>The descriptor of the created key.</returns>
        Task<KeyDescriptor> CreateSymmetricKey(IKeyConnector keyConnector);

        /// <summary>
        /// Retrieves the symmetric key associated with the specified key descriptor from the key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector to retrieve the key from.</param>
        /// <param name="keyDescriptor">The descriptor of the key to retrieve.</param>
        /// <returns>The symmetric key.</returns>
        Task<SymmetricKey> GetSymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor);

        /// <summary>
        /// Imports an asymmetric key into the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector to import the key into.</param>
        /// <param name="key">The asymmetric key to import.</param>
        /// <returns>The descriptor of the imported key.</returns>
        Task<KeyDescriptor> ImportAsymmetricKey(IKeyConnector keyConnector, AsymmetricKey key);

        /// <summary>
        /// Creates a new asymmetric key using the specified key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector to create the key with.</param>
        /// <returns>The descriptor of the created key.</returns>
        Task<KeyDescriptor> CreateAsymmetricKey(IKeyConnector keyConnector);

        /// <summary>
        /// Retrieves the asymmetric key associated with the specified key descriptor from the key connector.
        /// </summary>
        /// <param name="keyConnector">The key connector to retrieve the key from.</param>
        /// <param name="keyDescriptor">The descriptor of the key to retrieve.</param>
        /// <param name="exportPrivate">A flag indicating whether to export the private key. Default is <c>false</c>.</param>
        /// <returns>The asymmetric key.</returns>
        Task<AsymmetricKey> GetAsymmetricKey(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, bool exportPrivate = false);

        /// <summary>
        /// Signs the specified data using the key associated with the specified key descriptor.
        /// </summary>
        /// <param name="keyConnector">The key connector to sign the data with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for signing.</param>
        /// <param name="data">The data to sign.</param>
        /// <returns>The signature of the data.</returns>
        Task<byte[]> SignData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, byte[] data);

        /// <summary>
        /// Verifies the signature of the specified data using the key associated with the specified key descriptor.
        /// </summary>
        /// <param name="keyConnector">The key connector to verify the data with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for verification.</param>
        /// <param name="data">The data to verify.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        Task<bool> VerifyData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, byte[] data, byte[] signature);

        /// <summary>
        /// Signs the specified entity using the key associated with the specified key descriptor.
        /// </summary>
        /// <typeparam name="TEntitySigned">The type of the entity to sign.</typeparam>
        /// <param name="keyConnector">The key connector to sign the entity with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for signing.</param>
        /// <param name="entity">The entity to sign.</param>
        /// <returns>The signed entity.</returns>
        Task<TEntitySigned> SignEntity<TEntitySigned>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, TEntitySigned entity) where TEntitySigned : IEntitySigned;

        /// <summary>
        /// Verifies the signature of the specified entity using the key associated with the specified key descriptor.
        /// </summary>
        /// <typeparam name="TEntitySigned">The type of the entity to verify.</typeparam>
        /// <param name="keyConnector">The key connector to verify the entity with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for verification.</param>
        /// <param name="entity">The entity to verify.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        Task<bool> VerifyEntity<TEntitySigned>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, TEntitySigned entity) where TEntitySigned : IEntitySigned;

        /// <summary>
        /// Encrypts the specified data using the key associated with the specified key descriptor.
        /// </summary>
        /// <param name="keyConnector">The key connector to encrypt the data with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for encryption.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        Task<SymmetricData> EncryptData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, byte[] data);

        /// <summary>
        /// Decrypts the specified data using the key associated with the specified key descriptor.
        /// </summary>
        /// <param name="keyConnector">The key connector to decrypt the data with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for decryption.</param>
        /// <param name="data">The data to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        Task<byte[]> DecryptData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, SymmetricData data);

        /// <summary>
        /// Encrypts the specified data using the specified key connector, key descriptor, and public key bytes. Leverages key agreement protocol
        /// to derive a symmetric key based on the sender's asymmetric key and the recipient's asymmetric public key.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The sender's key descriptor.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="publicKeyBytes">The recipient's public key bytes.</param>
        /// <returns>The encrypted data.</returns>
        Task<SymmetricData> EncryptData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, byte[] data, byte[] publicKey);

        /// <summary>
        /// Decrypts the specified data using the specified key connector, key descriptor, and public key bytes. Leverages key agreement protocol
        /// to derive a symmetric key based on the sender's asymmetric key and the recipient's asymmetric public key.
        /// </summary>
        /// <param name="keyConnector">The key connector.</param>
        /// <param name="keyDescriptor">The sender's key descriptor.</param>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="publicKeyBytes">The recipient's public key bytes.</param>
        /// <returns>The decrypted data.</returns>
        Task<byte[]> DecryptData(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, SymmetricData data, byte[] publicKey);

        /// <summary>
        /// Encrypts the specified entity using the key associated with the specified key descriptor.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to encrypt.</typeparam>
        /// <param name="keyConnector">The key connector to encrypt the entity with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for encryption.</param>
        /// <param name="entity">The entity to encrypt.</param>
        /// <returns>The encrypted entity.</returns>
        Task<SymmetricEntity<TEntity>> EncryptEntity<TEntity>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, TEntity entity) where TEntity : IEntity;

        /// <summary>
        /// Decrypts the specified entity using the key associated with the specified key descriptor.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to decrypt.</typeparam>
        /// <param name="keyConnector">The key connector to decrypt the entity with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for decryption.</param>
        /// <param name="symmetricEntity">The symmetric entity to decrypt.</param>
        /// <returns>The decrypted entity.</returns>
        Task<TEntity> DecryptEntity<TEntity>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, SymmetricEntity<TEntity> symmetricEntity) where TEntity : IEntity;

        /// <summary>
        /// Encrypts the specified entity using the key associated with the specified key descriptor and the provided public key.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to encrypt.</typeparam>
        /// <param name="keyConnector">The key connector to encrypt the entity with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for encryption.</param>
        /// <param name="entity">The entity to encrypt.</param>
        /// <param name="publicKey">The public key to use for encryption.</param>
        /// <returns>The encrypted entity.</returns>
        Task<SymmetricEntity<TEntity>> EncryptEntity<TEntity>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, TEntity entity, byte[] publicKey) where TEntity : IEntity;

        /// <summary>
        /// Decrypts the specified entity using the key associated with the specified key descriptor and the provided public key.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to decrypt.</typeparam>
        /// <param name="keyConnector">The key connector to decrypt the entity with.</param>
        /// <param name="keyDescriptor">The descriptor of the key to use for decryption.</param>
        /// <param name="symmetricEntity">The symmetric entity to decrypt.</param>
        /// <param name="publicKey">The public key to use for decryption.</param>
        /// <returns>The decrypted entity.</returns>
        Task<TEntity> DecryptEntity<TEntity>(IKeyConnector keyConnector, KeyDescriptor keyDescriptor, SymmetricEntity<TEntity> symmetricEntity, byte[] publicKey) where TEntity : IEntity;

        #endregion

    }

}
