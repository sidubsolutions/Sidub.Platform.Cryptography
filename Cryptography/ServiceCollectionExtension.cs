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

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sidub.Platform.Core;
using Sidub.Platform.Cryptography.Providers;
using Sidub.Platform.Cryptography.Services;

#endregion

namespace Sidub.Platform.Cryptography
{

    /// <summary>
    /// Provides extension methods for configuring cryptography services in the service collection.
    /// </summary>
    public static class ServiceCollectionExtension
    {

        #region Public static methods

        /// <summary>
        /// Adds the Sidub cryptography services to the service collection.
        /// </summary>
        /// <param name="services">The service collection to add the cryptography services to.</param>
        /// <returns>The modified service collection.</returns>
        public static IServiceCollection AddSidubCryptography(
            this IServiceCollection services)
        {
            services.AddSidubPlatform();
            services.TryAddEnumerable(ServiceDescriptor.Transient<ICryptographyProvider, FilesystemKeyProvider>());
            services.TryAddEnumerable(ServiceDescriptor.Scoped<ICryptographyProvider, EphemeralKeyProvider>());

            services.TryAddTransient<ICryptographyService, CryptographyService>();

            return services;
        }

        #endregion

    }

}
