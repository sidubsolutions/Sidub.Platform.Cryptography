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

using Sidub.Platform.Core.Attributes;
using Sidub.Platform.Core.Entity;

#endregion

namespace Sidub.Platform.Cryptography
{

    /// <summary>
    /// Represents an asymmetric key used in cryptography.
    /// </summary>
    [Entity("AsymmetricKey")]
    public class AsymmetricKey : IEntity
    {

        #region Public properties

        /// <summary>
        /// Gets or sets the unique identifier of the asymmetric key.
        /// </summary>
        [EntityKey<Guid>("id")]
        public Guid Id { get; set; }

        /// <summary>
        /// Gets or sets the version of the asymmetric key.
        /// </summary>
        [EntityKey<string>("Version")]
        public string? Version { get; set; }

        /// <summary>
        /// Gets or sets the public key of the asymmetric key.
        /// </summary>
        [EntityField<byte[]>("PublicKey")]
        public byte[] PublicKey { get; set; }

        /// <summary>
        /// Gets or sets the private key of the asymmetric key.
        /// </summary>
        [EntityField<byte[]>("PrivateKey")]
        public byte[]? PrivateKey { get; set; }

        /// <summary>
        /// Gets a value indicating whether the asymmetric key has a private key.
        /// </summary>
        public bool IsPrivateKey { get => PrivateKey is not null; }

        /// <summary>
        /// Gets or sets a value indicating whether the asymmetric key was retrieved from storage.
        /// </summary>
        public bool IsRetrievedFromStorage { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKey"/> class.
        /// </summary>
        public AsymmetricKey()
        {
            Id = Guid.Empty;
            Version = string.Empty;
            PublicKey = Array.Empty<byte>();
            PrivateKey = Array.Empty<byte>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKey"/> class with the specified id, public key, and optional private key.
        /// </summary>
        /// <param name="id">The unique identifier of the asymmetric key.</param>
        /// <param name="publicKey">The public key of the asymmetric key.</param>
        /// <param name="privateKey">The private key of the asymmetric key.</param>
        public AsymmetricKey(Guid id, byte[] publicKey, byte[]? privateKey = null)
        {
            Id = id;
            Version = string.Empty;
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }

        #endregion

    }

}
