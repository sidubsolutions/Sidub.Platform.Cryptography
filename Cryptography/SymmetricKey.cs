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
    /// Represents a symmetric key used for cryptography.
    /// </summary>
    [Entity("SymmetricKey")]
    public class SymmetricKey : IEntity
    {

        #region Public properties

        /// <summary>
        /// Gets or sets the unique identifier of the symmetric key.
        /// </summary>
        [EntityKey<Guid>("id")]
        public Guid Id { get; set; }

        /// <summary>
        /// Gets or sets the version of the symmetric key.
        /// </summary>
        [EntityKey<string>("Version")]
        public string? Version { get; set; }

        /// <summary>
        /// Gets or sets the actual key value of the symmetric key.
        /// </summary>
        [EntityField<byte[]>("Key")]
        public byte[] Key { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the symmetric key is retrieved from storage.
        /// </summary>
        public bool IsRetrievedFromStorage { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKey"/> class.
        /// </summary>
        public SymmetricKey()
        {
            Id = Guid.Empty;
            Version = string.Empty;
            Key = Array.Empty<byte>();
            IsRetrievedFromStorage = false;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKey"/> class with the specified identifier and key.
        /// </summary>
        /// <param name="id">The unique identifier of the symmetric key.</param>
        /// <param name="key">The actual key value of the symmetric key.</param>
        public SymmetricKey(Guid id, byte[] key)
        {
            Id = id;
            Version = string.Empty;
            Key = key;
            IsRetrievedFromStorage = false;
        }

        #endregion

    }

}
