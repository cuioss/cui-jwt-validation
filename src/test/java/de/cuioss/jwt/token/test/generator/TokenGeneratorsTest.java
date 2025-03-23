/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.test.generator;

import de.cuioss.jwt.token.JwksAwareTokenParserImplTest;
import de.cuioss.jwt.token.TokenFactory;
import de.cuioss.test.generator.TypedGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the TokenGenerators factory and the generators it provides.
 */
class TokenGeneratorsTest {

    private TokenFactory tokenFactory;

    @BeforeEach
    void init() {
        tokenFactory = TokenFactory.builder().addParser(JwksAwareTokenParserImplTest.getValidJWKSParserWithLocalJWKS()).build();
    }

    @Test
    @DisplayName("Should generate valid access tokens")
    void shouldGenerateValidAccessTokens() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.accessTokens();

        // When
        String token = generator.next();

        // Then
        assertNotNull(token, "Token should not be null");
        var parsedToken = tokenFactory.createAccessToken(token);
        assertTrue(parsedToken.isPresent(), "Token should be parseable");
    }

    @Test
    @DisplayName("Should generate valid ID tokens")
    void shouldGenerateValidIdTokens() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.idTokens();

        // When
        String token = generator.next();

        // Then
        assertNotNull(token, "Token should not be null");
        var parsedToken = tokenFactory.createAccessToken(token);
        assertTrue(parsedToken.isPresent(), "Token should be parseable");
    }

    @Test
    @DisplayName("Should generate valid refresh tokens")
    void shouldGenerateValidRefreshTokens() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.refreshTokens();

        // When
        String token = generator.next();

        // Then
        assertNotNull(token, "Token should not be null");
        var parsedToken = tokenFactory.createAccessToken(token);
        assertTrue(parsedToken.isPresent(), "Token should be parseable");
    }

    @Test
    @DisplayName("Should generate valid JWKS")
    void shouldGenerateValidJwks() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.jwks();

        // When
        String jwks = generator.next();

        // Then
        assertNotNull(jwks, "JWKS should not be null");
        assertTrue(jwks.contains("\"keys\""), "JWKS should contain keys array");
        assertTrue(jwks.contains("\"kty\":\"RSA\""), "JWKS should contain RSA key type");
    }

    @Test
    @DisplayName("Should generate valid scopes")
    void shouldGenerateValidScopes() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.scopes();

        // When
        String scopes = generator.next();

        // Then
        assertNotNull(scopes, "Scopes should not be null");
        assertTrue(scopes.contains("openid"), "Scopes should contain openid");
    }

    @Test
    @DisplayName("Should generate valid roles")
    void shouldGenerateValidRoles() {
        // Given
        TypedGenerator<Set<String>> generator = TokenGenerators.roles();

        // When
        Set<String> roles = generator.next();

        // Then
        assertNotNull(roles, "Roles should not be null");
        assertFalse(roles.isEmpty(), "Roles should not be empty");
    }

    @Test
    @DisplayName("Should generate valid groups")
    void shouldGenerateValidGroups() {
        // Given
        TypedGenerator<Set<String>> generator = TokenGenerators.groups();

        // When
        Set<String> groups = generator.next();

        // Then
        assertNotNull(groups, "Groups should not be null");
        assertFalse(groups.isEmpty(), "Groups should not be empty");
    }

    @Test
    @DisplayName("Should generate valid alternative tokens")
    void shouldGenerateValidAlternativeTokens() {
        // Given
        TypedGenerator<String> accessTokenGenerator = TokenGenerators.alternativeAccessTokens();
        TypedGenerator<String> idTokenGenerator = TokenGenerators.alternativeIdTokens();
        TypedGenerator<String> refreshTokenGenerator = TokenGenerators.alternativeRefreshTokens();
        TypedGenerator<String> jwksGenerator = TokenGenerators.alternativeJwks();

        // When
        String accessToken = accessTokenGenerator.next();
        String idToken = idTokenGenerator.next();
        String refreshToken = refreshTokenGenerator.next();
        String jwks = jwksGenerator.next();

        // Then
        assertNotNull(accessToken, "Access token should not be null");
        assertNotNull(idToken, "ID token should not be null");
        assertNotNull(refreshToken, "Refresh token should not be null");
        assertNotNull(jwks, "JWKS should not be null");

        var alternativeTokenFactory = TokenFactory.builder().addParser(JwksAwareTokenParserImplTest.getValidJWKSParserWithAlternativeLocalJWKS()).build();
        // Verify tokens are parseable
        assertTrue(alternativeTokenFactory.createAccessToken(accessToken).isPresent(), "Access token should be parseable");
        assertTrue(alternativeTokenFactory.createIdToken(idToken).isPresent(), "ID token should be parseable");
        assertTrue(alternativeTokenFactory.createRefreshToken(refreshToken).isPresent(), "Refresh token should be parseable");

        // Verify JWKS contains alternative key ID
        assertTrue(jwks.contains("test-key-id"), "JWKS should contain alternative key ID");
    }
}