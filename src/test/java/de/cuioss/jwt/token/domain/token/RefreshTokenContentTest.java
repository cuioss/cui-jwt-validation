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
package de.cuioss.jwt.token.domain.token;

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.claim.ClaimValue;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.jwt.token.test.generator.ClaimValueGenerator;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.valueobjects.junit5.contracts.ShouldHandleObjectContracts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link RefreshTokenContent}.
 */
@DisplayName("Tests RefreshTokenContent functionality")
class RefreshTokenContentTest implements ShouldHandleObjectContracts<RefreshTokenContent> {

    private static final String SAMPLE_TOKEN = TestTokenProducer.validSignedEmptyJWT();

    @Test
    @DisplayName("Should create RefreshTokenContent with valid token")
    void shouldCreateRefreshTokenContentWithValidToken() {
        // Given a valid token
        var token = SAMPLE_TOKEN;
        Map<String, ClaimValue> claims = Collections.emptyMap();

        // When creating a RefreshTokenContent
        var refreshTokenContent = new RefreshTokenContent(token, claims);

        // Then the content should be correctly initialized
        assertNotNull(refreshTokenContent, "RefreshTokenContent should not be null");
        assertEquals(token, refreshTokenContent.getRawToken(), "Raw token should match");
        assertEquals(TokenType.REFRESH_TOKEN, refreshTokenContent.getTokenType(), "Token type should be REFRESH_TOKEN");
        assertNotNull(refreshTokenContent.getClaims(), "Claims should not be null");
        assertTrue(refreshTokenContent.getClaims().isEmpty(), "Claims should be empty");
    }

    @Test
    @DisplayName("Should create RefreshTokenContent with claims")
    void shouldCreateRefreshTokenContentWithClaims() {
        // Given a valid token and claims
        var token = SAMPLE_TOKEN;
        Map<String, ClaimValue> claims = new HashMap<>();
        String testValue = "test-value";
        claims.put("test-claim", ClaimValue.forPlainString(testValue));

        // When creating a RefreshTokenContent
        var refreshTokenContent = new RefreshTokenContent(token, claims);

        // Then the content should be correctly initialized with claims
        assertNotNull(refreshTokenContent, "RefreshTokenContent should not be null");
        assertEquals(token, refreshTokenContent.getRawToken(), "Raw token should match");
        assertEquals(TokenType.REFRESH_TOKEN, refreshTokenContent.getTokenType(), "Token type should be REFRESH_TOKEN");
        assertNotNull(refreshTokenContent.getClaims(), "Claims should not be null");
        assertFalse(refreshTokenContent.getClaims().isEmpty(), "Claims should not be empty");
        assertTrue(refreshTokenContent.getClaims().containsKey("test-claim"), "Claims should contain test-claim");
        assertEquals(testValue, refreshTokenContent.getClaims().get("test-claim").getOriginalString(), "Claim value should match");
    }

    @Override
    public RefreshTokenContent getUnderTest() {
        Map<String, ClaimValue> anyClaims = new HashMap<>();
        for (int i = 0; i < Generators.integers(0, 5).next(); i++) {
            anyClaims.put(Generators.nonEmptyStrings().next(), new ClaimValueGenerator().next());
        }
        return new RefreshTokenContent(Generators.nonEmptyStrings().next(), anyClaims);
    }
}
