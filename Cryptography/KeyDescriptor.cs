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
    /// Represents a key descriptor entity.
    /// </summary>
    [Entity("KeyDescriptor")]
    public record KeyDescriptor : IEntity
    {

        #region Public properties

        /// <summary>
        /// Gets or sets the unique identifier of the key descriptor.
        /// </summary>
        [EntityKey<Guid>("id")]
        public Guid Id { get; set; } = Guid.Empty;

        /// <summary>
        /// Gets or sets the version of the key descriptor.
        /// </summary>
        [EntityKey<string>("Version")]
        public string? Version { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether the key descriptor is retrieved from storage.
        /// </summary>
        public bool IsRetrievedFromStorage { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDescriptor"/> class.
        /// </summary>
        /// <remarks>
        /// This constructor is intended for IEntity use only.
        /// </remarks>
        [Obsolete("Parameterless constructor intended for IEntity use only.", true)]
        public KeyDescriptor()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDescriptor"/> class with the specified identifier and version.
        /// </summary>
        /// <param name="id">The unique identifier of the key descriptor.</param>
        /// <param name="version">The version of the key descriptor.</param>
        public KeyDescriptor(Guid id, string? version = null)
        {
            Id = id;
            Version = version;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDescriptor"/> class with the specified asymmetric key.
        /// </summary>
        /// <param name="key">The asymmetric key.</param>
        public KeyDescriptor(AsymmetricKey key)
        {
            Id = key.Id;
            Version = key.Version;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDescriptor"/> class with the specified symmetric key.
        /// </summary>
        /// <param name="key">The symmetric key.</param>
        public KeyDescriptor(SymmetricKey key)
        {
            Id = key.Id;
            Version = key.Version;
        }

        #endregion

    }

}
