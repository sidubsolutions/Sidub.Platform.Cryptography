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

using Sidub.Platform.Cryptography.Providers;

#endregion

namespace Sidub.Platform.Cryptography.Connectors
{

    /// <summary>
    /// Represents a connector for accessing keys stored in the filesystem.
    /// </summary>
    public class FilesystemKeyConnector : IKeyConnector<FilesystemKeyProvider>
    {

        #region Public properties

        /// <summary>
        /// Gets or sets the path to the key file.
        /// </summary>
        public string KeyPath { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="FilesystemKeyConnector"/> class with the specified key path.
        /// </summary>
        /// <param name="keyPath">The path to the key file.</param>
        public FilesystemKeyConnector(string keyPath)
        {
            KeyPath = keyPath;
        }

        #endregion

    }

}
