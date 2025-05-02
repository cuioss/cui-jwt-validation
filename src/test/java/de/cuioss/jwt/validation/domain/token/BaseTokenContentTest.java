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
package de.cuioss.jwt.validation.domain.token;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.test.TestTokenProducer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.Serial;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link BaseTokenContent}.
 */
@DisplayName("Tests BaseTokenContent functionality")
class BaseTokenContentTest {

    private static final String SAMPLE_TOKEN = TestTokenProducer.validSignedEmptyJWT();

    @Test
    @DisplayName("Should create BaseTokenContent with valid parameters")
    void shouldCreateBaseTokenContentWithValidParameters() {
        // Given valid parameters
        Map<String, ClaimValue> claims = new HashMap<>();
        String rawToken = SAMPLE_TOKEN;
        TokenType tokenType = TokenType.ACCESS_TOKEN;

        // When creating a BaseTokenContent
        var baseTokenContent = new TestBaseTokenContent(claims, rawToken, tokenType);

        // Then the content should be correctly initialized
        assertNotNull(baseTokenContent, "BaseTokenContent should not be null");
        assertEquals(claims, baseTokenContent.getClaims(), "Claims should match");
        assertEquals(rawToken, baseTokenContent.getRawToken(), "Raw validation should match");
        assertEquals(tokenType, baseTokenContent.getTokenType(), "Token type should match");
    }

    @Test
    @DisplayName("Should throw NullPointerException when claims is null")
    void shouldThrowExceptionWhenClaimsIsNull() {
        // When creating a BaseTokenContent with null claims
        // Then an exception should be thrown
        assertThrows(NullPointerException.class,
                () -> new TestBaseTokenContent(null, SAMPLE_TOKEN, TokenType.ACCESS_TOKEN),
                "Should throw NullPointerException for null claims");
    }

    @Test
    @DisplayName("Should return claim option correctly")
    void shouldReturnClaimOptionCorrectly() {
        // Given a BaseTokenContent with a claim
        Map<String, ClaimValue> claims = new HashMap<>();
        ClaimValue claimValue = ClaimValue.forPlainString("test-value");
        claims.put(ClaimName.ISSUER.getName(), claimValue);
        var baseTokenContent = new TestBaseTokenContent(claims, SAMPLE_TOKEN, TokenType.ACCESS_TOKEN);

        // When getting the claim option
        Optional<ClaimValue> claimOption = baseTokenContent.getClaimOption(ClaimName.ISSUER);

        // Then the claim option should be present and contain the correct value
        assertTrue(claimOption.isPresent(), "Claim option should be present");
        assertEquals(claimValue, claimOption.get(), "Claim value should match");
    }

    @Test
    @DisplayName("Should return empty claim option when claim is not present")
    void shouldReturnEmptyClaimOptionWhenClaimIsNotPresent() {
        // Given a BaseTokenContent without a specific claim
        Map<String, ClaimValue> claims = new HashMap<>();
        var baseTokenContent = new TestBaseTokenContent(claims, SAMPLE_TOKEN, TokenType.ACCESS_TOKEN);

        // When getting a claim option that doesn't exist
        Optional<ClaimValue> claimOption = baseTokenContent.getClaimOption(ClaimName.ISSUER);

        // Then the claim option should be empty
        assertTrue(claimOption.isEmpty(), "Claim option should be empty");
    }


    /**
     * Concrete implementation of BaseTokenContent for testing.
     */
    static class TestBaseTokenContent extends BaseTokenContent {
        @Serial
        private static final long serialVersionUID = 1L;

        TestBaseTokenContent(Map<String, ClaimValue> claims, String rawToken, TokenType tokenType) {
            super(claims, rawToken, tokenType);
        }
    }
}
