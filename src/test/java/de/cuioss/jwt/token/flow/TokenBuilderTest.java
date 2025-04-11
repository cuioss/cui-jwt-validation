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
package de.cuioss.jwt.token.flow;

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.token.RefreshTokenContent;
import de.cuioss.jwt.token.test.TestTokenProducer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenBuilder}.
 */
@DisplayName("Tests TokenBuilder functionality")
class TokenBuilderTest {

    private static final String SAMPLE_TOKEN = TestTokenProducer.validSignedEmptyJWT();

    private TokenBuilder tokenBuilder;

    @BeforeEach
    void setUp() {
        tokenBuilder = new TokenBuilder();
    }

    @Test
    @DisplayName("createRefreshToken should create RefreshTokenContent")
    void createRefreshTokenShouldCreateRefreshTokenContent() {
        // Given
        String token = SAMPLE_TOKEN;

        // When
        Optional<RefreshTokenContent> result = tokenBuilder.createRefreshToken(token);

        // Then
        assertTrue(result.isPresent(), "Should return RefreshTokenContent");
        RefreshTokenContent refreshTokenContent = result.get();

        // Verify token type
        assertEquals(TokenType.REFRESH_TOKEN, refreshTokenContent.getTokenType(), "Token type should be REFRESH_TOKEN");

        // Verify raw token
        assertEquals(token, refreshTokenContent.getRawToken(), "Raw token should match");
    }

    @Test
    @DisplayName("createAccessToken should handle null parameter")
    void createAccessTokenShouldHandleNullParameter() {
        // When/Then
        assertThrows(NullPointerException.class, () -> tokenBuilder.createAccessToken(null),
                "Should throw NullPointerException when decodedJwt is null");
    }

    @Test
    @DisplayName("createIdToken should handle null parameter")
    void createIdTokenShouldHandleNullParameter() {
        // When/Then
        assertThrows(NullPointerException.class, () -> tokenBuilder.createIdToken(null),
                "Should throw NullPointerException when decodedJwt is null");
    }

    @Test
    @DisplayName("createRefreshToken should handle null parameter")
    void createRefreshTokenShouldHandleNullParameter() {
        // When/Then
        assertThrows(NullPointerException.class, () -> tokenBuilder.createRefreshToken(null),
                "Should throw NullPointerException when rawToken is null");
    }
}
