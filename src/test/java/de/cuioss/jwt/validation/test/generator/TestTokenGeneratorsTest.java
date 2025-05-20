/*
 * Copyright 2025 the original author or authors.
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
package de.cuioss.jwt.validation.test.generator;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("TestTokenGenerators Tests")
class TestTokenGeneratorsTest {

    @Test
    @DisplayName("accessTokens() should create generator for ACCESS_TOKEN type")
    void accessTokensShouldCreateGeneratorForAccessTokenType() {
        // Given
        TypedGenerator<TestTokenHolder> generator = TestTokenGenerators.accessTokens();

        // When
        TestTokenHolder token = generator.next();

        // Then
        assertNotNull(token, "Generated token should not be null");
        assertEquals(TokenType.ACCESS_TOKEN, token.getTokenType(), "Token type should be ACCESS_TOKEN");

        // Verify token has required claims for ACCESS_TOKEN
        assertNotNull(token.getClaims(), "Claims should not be null");
        assertTrue(token.getClaims().containsKey("scope"), "ACCESS_TOKEN should have scope claim");

        // Verify token can be serialized to a JWT string
        String jwt = token.getRawToken();
        assertNotNull(jwt, "JWT string should not be null");
        assertFalse(jwt.isEmpty(), "JWT string should not be empty");
    }

    @Test
    @DisplayName("idTokens() should create generator for ID_TOKEN type")
    void idTokensShouldCreateGeneratorForIdTokenType() {
        // Given
        TypedGenerator<TestTokenHolder> generator = TestTokenGenerators.idTokens();

        // When
        TestTokenHolder token = generator.next();

        // Then
        assertNotNull(token, "Generated token should not be null");
        assertEquals(TokenType.ID_TOKEN, token.getTokenType(), "Token type should be ID_TOKEN");

        // Verify token has required claims for ID_TOKEN
        assertNotNull(token.getClaims(), "Claims should not be null");
        assertTrue(token.getClaims().containsKey("aud"), "ID_TOKEN should have audience claim");

        // Verify token can be serialized to a JWT string
        String jwt = token.getRawToken();
        assertNotNull(jwt, "JWT string should not be null");
        assertFalse(jwt.isEmpty(), "JWT string should not be empty");
    }

    @Test
    @DisplayName("refreshTokens() should create generator for REFRESH_TOKEN type")
    void refreshTokensShouldCreateGeneratorForRefreshTokenType() {
        // Given
        TypedGenerator<TestTokenHolder> generator = TestTokenGenerators.refreshTokens();

        // When
        TestTokenHolder token = generator.next();

        // Then
        assertNotNull(token, "Generated token should not be null");
        assertEquals(TokenType.REFRESH_TOKEN, token.getTokenType(), "Token type should be REFRESH_TOKEN");

        // Verify token has required claims for REFRESH_TOKEN
        assertNotNull(token.getClaims(), "Claims should not be null");

        // Verify token can be serialized to a JWT string
        String jwt = token.getRawToken();
        assertNotNull(jwt, "JWT string should not be null");
        assertFalse(jwt.isEmpty(), "JWT string should not be empty");
    }
}