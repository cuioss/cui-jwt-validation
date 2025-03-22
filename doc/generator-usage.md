# Using Generators in Tests

## Overview
This document describes how to use the generators provided in the `de.cuioss.jwt.token.test.generator` package to simplify test code and make it more robust.

## Available Generators

The following generators are available through the `TokenGenerators` factory:

- `accessTokens()`: Generates OAuth/OIDC access tokens with default settings
- `alternativeAccessTokens()`: Generates access tokens with alternative settings
- `idTokens()`: Generates OAuth/OIDC ID tokens with default settings
- `alternativeIdTokens()`: Generates ID tokens with alternative settings
- `refreshTokens()`: Generates OAuth/OIDC refresh tokens with default settings
- `alternativeRefreshTokens()`: Generates refresh tokens with alternative settings
- `jwks()`: Generates JWKS (JSON Web Key Sets) with default settings
- `alternativeJwks()`: Generates JWKS with alternative settings
- `scopes()`: Generates OAuth/OIDC scopes (space-separated strings)
- `roles()`: Generates sets of role strings
- `groups()`: Generates sets of group strings

## Benefits of Using Generators

Using generators in tests provides several benefits:

1. **Reduced Boilerplate**: No need to manually create tokens or other test data
2. **Increased Test Coverage**: Generators create random data, which helps test more scenarios
3. **Improved Maintainability**: Changes to token structure only need to be made in one place
4. **Better Readability**: Test code focuses on what's being tested, not how to create test data
5. **Consistency**: All tests use the same approach to create test data

## Example Usage

Here's an example of how to use the generators in a test:

```java
// Create an access token
TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
String accessToken = accessTokenGenerator.next();

// Create an ID token
TypedGenerator<String> idTokenGenerator = TokenGenerators.idTokens();
String idToken = idTokenGenerator.next();

// Create a refresh token
TypedGenerator<String> refreshTokenGenerator = TokenGenerators.refreshTokens();
String refreshToken = refreshTokenGenerator.next();

// Create a JWKS
TypedGenerator<String> jwksGenerator = TokenGenerators.jwks();
String jwks = jwksGenerator.next();

// Create scopes
TypedGenerator<String> scopeGenerator = TokenGenerators.scopes();
String scopes = scopeGenerator.next();

// Create roles
TypedGenerator<Set<String>> roleGenerator = TokenGenerators.roles();
Set<String> roles = roleGenerator.next();

// Create groups
TypedGenerator<Set<String>> groupGenerator = TokenGenerators.groups();
Set<String> groups = groupGenerator.next();
```

## Test Classes Using Generators

The following test classes have been updated to use generators:

- `ParsedAccessTokenTest`: Uses generators for access tokens, ID tokens, and other test data

## Test Classes That Could Benefit from Using Generators

The following test classes could benefit from using generators:

- `JwksAwareTokenParserImplTest`: Could use generators for access tokens and JWKS
- `TokenFactoryTest`: Could use generators for access tokens, ID tokens, and refresh tokens
- `ParsedRefreshTokenTest`: Could use generators for refresh tokens
- `ParsedTokenTest`: Could use generators for access tokens
- `MultiIssuerJwtParserTest`: Could use generators for access tokens
- `ParsedIdTokenTest`: Could use generators for ID tokens
- `TestTokenProducerTest`: Could use generators for various token types

## Implementation Details

The generators are implemented as `TypedGenerator<T>` classes in the `de.cuioss.jwt.token.test.generator` package. They use the `TestTokenProducer` and `JWKSFactory` classes to create the actual tokens and JWKS.

The `TokenGenerators` factory provides a unified access point to all generators, making it easy to use them in tests.