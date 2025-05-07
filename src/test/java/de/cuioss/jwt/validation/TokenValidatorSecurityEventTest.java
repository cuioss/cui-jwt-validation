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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.security.AlgorithmPreferences;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.jwt.validation.test.TestTokenProducer;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the security event counting functionality in {@link TokenValidator}.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li>CUI-JWT-7.1: Security Event Tracking</li>
 *   <li>CUI-JWT-7.2: Monitoring of Token Validation Failures</li>
 *   <li>CUI-JWT-7.3: Detection of Potential Security Incidents</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see <a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/specification/security.adoc">Security Specification</a>
 */
@EnableTestLogger
@DisplayName("Tests TokenValidator security event counting")
class TokenValidatorSecurityEventTest {

    private static final String ISSUER = TestTokenProducer.ISSUER;
    private static final String AUDIENCE = "test-client";
    private static final String CLIENT_ID = "test-client";

    private TokenValidator tokenValidator;

    @BeforeEach
    void setUp() {
        // Create a JWKSKeyLoader with the default JWKS content
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();

        // Create issuer config
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .expectedClientId(CLIENT_ID)
                .jwksContent(jwksContent)
                .algorithmPreferences(new AlgorithmPreferences())
                .build();

        // Create validation factory
        tokenValidator = new TokenValidator(issuerConfig);
    }

    @Test
    @DisplayName("Should count empty validation events")
    void shouldCountEmptyTokenEvents() {
        // Get initial count
        long initialCount = tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY);

        // Process empty validation
        tokenValidator.createAccessToken("");

        // Verify count increased
        assertEquals(initialCount + 1, tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));

        // Process another empty validation
        tokenValidator.createRefreshToken("   ");

        // Verify count increased again
        assertEquals(initialCount + 2, tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
    }

    @Test
    @DisplayName("Should count failed to decode JWT events")
    void shouldCountFailedToDecodeJwtEvents() {
        // Get initial count
        long initialCount = tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT);

        // Process invalid validation
        tokenValidator.createAccessToken("invalid-validation");

        // Verify count increased
        assertEquals(initialCount + 1, tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT));
    }

    @Test
    @DisplayName("Should count missing claim events")
    void shouldCountMissingClaimEvents() {
        // Get initial count
        long initialCount = tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

        // Create a validation without issuer
        String token = Jwts.builder()
                .subject("test-subject")
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey())
                .compact();

        // Process validation without issuer
        tokenValidator.createAccessToken(token);

        // Verify count increased
        assertTrue(tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.MISSING_CLAIM) > initialCount,
                "Missing claim count should increase");
    }

    @Test
    @DisplayName("Should count no issuer config events")
    void shouldCountNoIssuerConfigEvents() {
        // Get initial count
        long initialCount = tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.NO_ISSUER_CONFIG);

        // Create a validation with unknown issuer
        String token = Jwts.builder()
                .issuer("https://unknown-issuer.com")
                .subject("test-subject")
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey())
                .compact();

        // Process validation with unknown issuer
        tokenValidator.createAccessToken(token);

        // Verify count increased
        assertEquals(initialCount + 1, tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.NO_ISSUER_CONFIG));
    }

    @Test
    @DisplayName("Should count signature validation failed events")
    void shouldCountSignatureValidationFailedEvents() {
        // Get initial count
        long initialCount = tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);

        // Create a validation with invalid signature
        String validToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        String invalidToken = validToken.substring(0, validToken.lastIndexOf('.') + 1) + "invalid-signature";

        // Process validation with invalid signature
        tokenValidator.createAccessToken(invalidToken);

        // Verify count increased
        assertTrue(tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED) > initialCount,
                "Signature validation failed count should increase");
    }

    @Test
    @DisplayName("Should reset security event counters")
    void shouldResetSecurityEventCounters() {
        // Generate some events
        tokenValidator.createAccessToken("");
        tokenValidator.createAccessToken("invalid-validation");

        // Verify counts are non-zero
        assertTrue(tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY) > 0);
        assertTrue(tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT) > 0);

        // Reset counters
        tokenValidator.getSecurityEventCounter().reset();

        // Verify counts are zero
        assertEquals(0, tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
        assertEquals(0, tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT));
    }
}
