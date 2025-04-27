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

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

class ValidTokenContentGeneratorTest {

    @Test
    void shouldGenerateValidAccessToken() {
        // Given
        ValidTokenContentGenerator generator = new ValidTokenContentGenerator(TokenType.ACCESS_TOKEN);

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertEquals(TokenType.ACCESS_TOKEN, token.getTokenType());
        assertNotNull(token.getRawToken());
        assertTrue(token.getRawToken().startsWith("valid-validation-"));

        // Verify mandatory claims for ACCESS_TOKEN
        assertNotNull(token.getIssuer());
        assertNotNull(token.getSubject());
        assertNotNull(token.getExpirationTime());
        assertNotNull(token.getIssuedAtTime());
        assertFalse(token.isExpired());

        // Verify scope claim (mandatory for ACCESS_TOKEN)
        assertTrue(token.getClaimOption(ClaimName.SCOPE).isPresent());
        String scopeValue = token.getClaimOption(ClaimName.SCOPE).get().getOriginalString();
        assertNotNull(scopeValue);
        Collection<String> scopes = ScopeGenerator.splitScopes(scopeValue);
        assertFalse(scopes.isEmpty());
        assertTrue(scopes.contains("openid"), "ACCESS_TOKEN should contain 'openid' scope");
    }

    @Test
    void shouldGenerateValidIdToken() {
        // Given
        ValidTokenContentGenerator generator = new ValidTokenContentGenerator(TokenType.ID_TOKEN);

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertEquals(TokenType.ID_TOKEN, token.getTokenType());
        assertNotNull(token.getRawToken());
        assertTrue(token.getRawToken().startsWith("valid-validation-"));

        // Verify mandatory claims for ID_TOKEN
        assertNotNull(token.getIssuer());
        assertNotNull(token.getSubject());
        assertNotNull(token.getExpirationTime());
        assertNotNull(token.getIssuedAtTime());
        assertFalse(token.isExpired());

        // Verify audience claim (mandatory for ID_TOKEN)
        assertTrue(token.getClaimOption(ClaimName.AUDIENCE).isPresent());

        // Verify optional claims typical for ID tokens
        assertTrue(token.getClaimOption(ClaimName.EMAIL).isPresent());
        assertTrue(token.getClaimOption(ClaimName.NAME).isPresent());
        assertTrue(token.getClaimOption(ClaimName.PREFERRED_USERNAME).isPresent());
    }

    @Test
    void shouldGenerateValidRefreshToken() {
        // Given
        ValidTokenContentGenerator generator = new ValidTokenContentGenerator(TokenType.REFRESH_TOKEN);

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertEquals(TokenType.REFRESH_TOKEN, token.getTokenType());
        assertNotNull(token.getRawToken());
        assertTrue(token.getRawToken().startsWith("valid-validation-"));

        // Verify common claims
        assertNotNull(token.getIssuer());
        assertNotNull(token.getSubject());
        assertNotNull(token.getExpirationTime());
        assertNotNull(token.getIssuedAtTime());
        assertFalse(token.isExpired());
    }

    @Test
    void shouldUseDefaultTokenType() {
        // Given
        ValidTokenContentGenerator generator = new ValidTokenContentGenerator();

        // When
        TokenContent token = generator.next();

        // Then
        assertNotNull(token);
        assertEquals(TokenType.ACCESS_TOKEN, token.getTokenType());
    }
}
