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
package de.cuioss.jwt.validation.test.generator;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.token.TokenContent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InvalidTokenContentGeneratorTest {

    @Test
    void shouldGenerateTokenWithMissingIssuer() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator()
                .withMissingIssuer();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertEquals(TokenType.ACCESS_TOKEN, token.getTokenType());
        assertFalse(token.getClaimOption(ClaimName.ISSUER).isPresent());

        // Verify that getIssuer() throws exception due to missing issuer
        assertThrows(IllegalStateException.class, token::getIssuer);
    }

    @Test
    void shouldGenerateTokenWithMissingSubject() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator()
                .withMissingSubject();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertFalse(token.getClaimOption(ClaimName.SUBJECT).isPresent());

        // Verify that getSubject() throws exception due to missing subject
        assertThrows(IllegalStateException.class, token::getSubject);
    }

    @Test
    void shouldGenerateTokenWithMissingExpiration() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator()
                .withMissingExpiration();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertFalse(token.getClaimOption(ClaimName.EXPIRATION).isPresent());

        // Verify that getExpirationTime() throws exception due to missing expiration
        assertThrows(IllegalStateException.class, token::getExpirationTime);
    }

    @Test
    void shouldGenerateExpiredToken() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator()
                .withExpiredToken();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertTrue(token.getClaimOption(ClaimName.EXPIRATION).isPresent());
        assertTrue(token.isExpired(), "Token should be expired");
    }

    @Test
    void shouldGenerateTokenWithMissingIssuedAt() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator()
                .withMissingIssuedAt();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertFalse(token.getClaimOption(ClaimName.ISSUED_AT).isPresent());

        // Verify that getIssuedAtTime() throws exception due to missing issued at time
        assertThrows(IllegalStateException.class, token::getIssuedAtTime);
    }

    @Test
    void shouldGenerateTokenWithMissingTokenType() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator()
                .withMissingTokenType();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertFalse(token.getClaimOption(ClaimName.TYPE).isPresent());
    }

    @Test
    void shouldGenerateAccessTokenWithMissingScope() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator(TokenType.ACCESS_TOKEN)
                .withMissingScope();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertEquals(TokenType.ACCESS_TOKEN, token.getTokenType());
        assertFalse(token.getClaimOption(ClaimName.SCOPE).isPresent());
    }

    @Test
    void shouldGenerateIdTokenWithMissingAudience() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator(TokenType.ID_TOKEN)
                .withMissingAudience();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertEquals(TokenType.ID_TOKEN, token.getTokenType());
        assertFalse(token.getClaimOption(ClaimName.AUDIENCE).isPresent());
    }

    @Test
    void shouldResetMutationFlags() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator()
                .withMissingIssuer()
                .withMissingSubject();

        // When
        generator.reset();
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertTrue(token.getClaimOption(ClaimName.ISSUER).isPresent());
        assertTrue(token.getClaimOption(ClaimName.SUBJECT).isPresent());
    }

    @Test
    void shouldUseDefaultTokenType() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertEquals(TokenType.ACCESS_TOKEN, token.getTokenType());
    }

    @Test
    void shouldCombineMultipleMutations() {
        // Given
        InvalidTokenContentGenerator generator = new InvalidTokenContentGenerator()
                .withMissingIssuer()
                .withMissingSubject()
                .withExpiredToken();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertFalse(token.getClaimOption(ClaimName.ISSUER).isPresent());
        assertFalse(token.getClaimOption(ClaimName.SUBJECT).isPresent());
        assertTrue(token.isExpired());
    }
}