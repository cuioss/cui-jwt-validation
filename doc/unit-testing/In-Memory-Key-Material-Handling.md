# In-Memory Key Material Handling for JWT Validation

This package provides classes for in-memory key material handling for JWT token testing and validation. These classes are designed to replace the existing file-based key material handling with a more flexible, in-memory approach that supports multiple algorithms.

## Classes

### InMemoryKeyMaterialHandler

The `InMemoryKeyMaterialHandler` class provides access to private and public keys used for signing and verifying tokens. Unlike the original `KeyMaterialHandler`, this class:

- Creates keys on the fly
- Stores keys in static fields instead of the filesystem
- Supports multiple algorithms (RS256, RS384, RS512)
- Uses BouncyCastle for key material generation

#### Key Features

- **Multiple Algorithm Support**: Supports RS256, RS384, and RS512 algorithms
- **Dynamic Key Generation**: Generates keys on demand without requiring filesystem access
- **In-Memory Storage**: Stores keys in static fields for fast access
- **BouncyCastle Integration**: Uses BouncyCastle for cryptographic operations

#### Usage Examples

```java
// Get default private key for RS256
PrivateKey privateKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey();

// Get default public key for RS256
PublicKey publicKey = InMemoryKeyMaterialHandler.getDefaultPublicKey();

// Get private key for a specific algorithm
PrivateKey rs384PrivateKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey(InMemoryKeyMaterialHandler.Algorithm.RS384);

// Get public key for a specific algorithm
PublicKey rs384PublicKey = InMemoryKeyMaterialHandler.getDefaultPublicKey(InMemoryKeyMaterialHandler.Algorithm.RS384);

// Get private key for a specific algorithm and key ID
PrivateKey customPrivateKey = InMemoryKeyMaterialHandler.getPrivateKey(InMemoryKeyMaterialHandler.Algorithm.RS512, "custom-key-id");

// Create JWKS content for the default RS256 key
String jwks = InMemoryKeyMaterialHandler.createDefaultJwks();

// Create JWKS content for a specific algorithm
String rs384Jwks = InMemoryKeyMaterialHandler.createDefaultJwks(InMemoryKeyMaterialHandler.Algorithm.RS384);

// Create JWKS content with all supported algorithms
String multiAlgorithmJwks = InMemoryKeyMaterialHandler.createMultiAlgorithmJwks();

// Create a JwksLoader for the default RS256 key
JwksLoader jwksLoader = InMemoryKeyMaterialHandler.createDefaultJwksLoader();

// Create a JwksLoader for a specific algorithm
JwksLoader rs384JwksLoader = InMemoryKeyMaterialHandler.createDefaultJwksLoader(InMemoryKeyMaterialHandler.Algorithm.RS384, securityEventCounter);

// Create a JwksLoader with all supported algorithms
JwksLoader multiAlgorithmJwksLoader = InMemoryKeyMaterialHandler.createMultiAlgorithmJwksLoader(securityEventCounter);
```

### InMemoryJWKSFactory

The `InMemoryJWKSFactory` class provides factory methods for creating JWKS content for testing purposes. Unlike the original `JWKSFactory`, this class:

- Supports multiple algorithms (RS256, RS384, RS512)
- Creates keys on the fly
- Stores keys in static fields instead of the filesystem
- Uses BouncyCastle for key material generation

#### Key Features

- **Multiple Algorithm Support**: Supports RS256, RS384, and RS512 algorithms
- **Dynamic JWKS Generation**: Generates JWKS content on demand without requiring filesystem access
- **Compatibility**: Provides a similar API to the original JWKSFactory for backward compatibility

#### Usage Examples

```java
// Create JWKS content for the default RS256 key
String jwks = InMemoryJWKSFactory.createDefaultJwks();

// Create JWKS content for a specific algorithm
String rs384Jwks = InMemoryJWKSFactory.createDefaultJwks(InMemoryKeyMaterialHandler.Algorithm.RS384);

// Create JWKS content with a specific key ID
String customJwks = InMemoryJWKSFactory.createValidJwksWithKeyId("custom-key-id");

// Create JWKS content with a specific algorithm and key ID
String customRs384Jwks = InMemoryJWKSFactory.createValidJwksWithKeyId(InMemoryKeyMaterialHandler.Algorithm.RS384, "custom-key-id");

// Create JWKS content with all supported algorithms
String multiAlgorithmJwks = InMemoryJWKSFactory.createMultiAlgorithmJwks();

// Create a JwksLoader for the default RS256 key
JwksLoader jwksLoader = InMemoryJWKSFactory.createDefaultJwksLoader(securityEventCounter);

// Create a JwksLoader for a specific algorithm
JwksLoader rs384JwksLoader = InMemoryJWKSFactory.createJwksLoader(InMemoryKeyMaterialHandler.Algorithm.RS384, securityEventCounter);

// Create a JwksLoader with all supported algorithms
JwksLoader multiAlgorithmJwksLoader = InMemoryJWKSFactory.createMultiAlgorithmJwksLoader(securityEventCounter);
```

## Advantages Over the Original Implementation

1. **No Filesystem Dependency**: Keys are generated on the fly and stored in memory, eliminating the need for filesystem access.
2. **Multiple Algorithm Support**: Supports RS256, RS384, and RS512 algorithms, allowing for more comprehensive testing.
3. **Dynamic Key Generation**: Keys are generated on demand, making it easier to create keys with different algorithms and key IDs.
4. **Simplified Testing**: Provides a more flexible and easier-to-use API for testing JWT token validation.
5. **BouncyCastle Integration**: Uses BouncyCastle for cryptographic operations, ensuring consistent behavior across different environments.

## Migration Guide

To migrate from the original `KeyMaterialHandler` and `JWKSFactory` to the new in-memory implementation:

1. Replace `KeyMaterialHandler` with `InMemoryKeyMaterialHandler`
2. Replace `JWKSFactory` with `InMemoryJWKSFactory`
3. Update method calls to use the new API

### Example Migration

```java
// Before
String jwks = JWKSFactory.createDefaultJwks();
JwksLoader jwksLoader = KeyMaterialHandler.createDefaultJwksLoader();

// After
String jwks = InMemoryJWKSFactory.createDefaultJwks();
JwksLoader jwksLoader = InMemoryKeyMaterialHandler.createDefaultJwksLoader();
```

## Testing

The `InMemoryKeyHandlingTest` class provides tests for the `InMemoryKeyMaterialHandler` and `InMemoryJWKSFactory` classes. These tests verify that:

1. Keys can be generated for all supported algorithms
2. JWKS content can be created for each algorithm
3. Multi-algorithm JWKS content can be created
4. JwksLoaders can be created with the default key
5. Tokens can be created and verified with the default key
6. The InMemoryJWKSFactory can create valid JWKS content

To run the tests:

```bash
mvn test -Dtest=InMemoryKeyHandlingTest
```