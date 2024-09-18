# Sidub Platform - Cryptography

This repository contains the cryptography module for the Sidub Platform. It 
provides cryptographic functions for the platform including hashing, encryption,
signing and verification capabilities.

Abstractions and core concepts are defined within this library and
implementations against specific cryptographic services are provided in
the respective cryptography library (i.e., 
`Sidub.Platform.Cryptography.AzureKeyVault`).

> [!WARNING]
> No guarantees are made regarding the security of the cryptographic functions
> provided by this library. It is the responsibility of the user to ensure that
> the cryptographic functions are used correctly and securely, and satisfy all
> requirements for the intended use.

## Introduction
Cryptographic functionality is defined by the `ICryptographyService` interface
which may be injected into services requiring it. The service is supported by
various `ICryptographyProvider` implementations which provide the underlying
cryptographic operations.

Not all cryptographic providers support all operations. See the respective
documentation for supported operations.

### Registering a cryptography service
Cryptography services may be registered within the service registry, using the
a `CryptographyServiceReference` and `IKeyConnector` implementation associated
with the desired cryptographic provider.

For example, to register a ephemeral cryptography service, use the 
`EphemeralKeyConnector`; or, to register a file system based cryptography
service, use the `FilesystemKeyConnector`.

```csharp
serviceCollection.AddSidubPlatform(serviceProvider =>
{
    var metadata = new InMemoryServiceRegistry();

    var cryptographyReference = new CryptographyServiceReference("crypto");
    var keyConnector = new EphemeralKeyConnector();
    //var keyConnector = new FilesystemKeyConnector(@"C:\Keys\");
    metadata.RegisterServiceReference(cryptographyReference, keyConnector);

    return metadata;
});
```

### Performing cryptographic operations
Cryptographic operations are provided through the `ICryptographyService`
implementation and operate against a provided `CryptographyServiceReference`
which designates which cryptography service to use.

Various cryptographic operations are available:
 - Get / create / import symmetric key
 - Get / create / import asymmetric key
 - Encrypt / decrypt data using symmetric key
 - Encrypt / decrypt entities using symmetric key
 - Encrypt / decrypt data using asymmetric key exchange
 - Encrypt / decrypt entities using asymmetric key exchange
 - Sign / verify data using asymmetric key
 - Sign / verify entities using asymmetric key

See the specific documentation for details on how to use the cryptographic
operations.

## License
This project is dual-licensed under the AGPL v3 or a proprietary license. For
details, see [https://sidub.ca/licensing](https://sidub.ca/licensing) or the 
LICENSE.txt file.
