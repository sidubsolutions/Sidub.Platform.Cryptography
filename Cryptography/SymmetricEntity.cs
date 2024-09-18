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

#endregion

namespace Sidub.Platform.Cryptography
{

    /// <summary>
    /// Represents a symmetric entity that inherits from SymmetricData.
    /// </summary>
    /// <typeparam name="TEntity">The type of the entity.</typeparam>
    public class SymmetricEntity<TEntity> : SymmetricData where TEntity : IEntity
    {

        #region Public static methods

        /// <summary>
        /// Creates a new SymmetricEntity instance from a SymmetricData object.
        /// </summary>
        /// <param name="data">The SymmetricData object to create from.</param>
        /// <returns>A new SymmetricEntity instance.</returns>
        public static SymmetricEntity<TEntity> CreateFromSymmetricData(SymmetricData data)
        {
            return new SymmetricEntity<TEntity>()
            {
                InitializationVector = data.InitializationVector,
                CipherText = data.CipherText
            };
        }

        #endregion

    }

}
