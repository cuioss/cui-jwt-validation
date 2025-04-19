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
package de.cuioss.jwt.token;

import de.cuioss.jwt.token.flow.IssuerConfig;
import de.cuioss.jwt.token.flow.TokenFactoryConfig;
import de.cuioss.jwt.token.security.AlgorithmPreferences;
import de.cuioss.jwt.token.security.SecurityEventCounter;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.KeyMaterialHandler;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the security event counting functionality in {@link TokenFactory}.
 */
@EnableTestLogger
@DisplayName("Tests TokenFactory security event counting")
class TokenFactorySecurityEventTest {

    private static final String ISSUER = TestTokenProducer.ISSUER;
    private static final String AUDIENCE = "test-client";
    private static final String CLIENT_ID = "test-client";

    private TokenFactory tokenFactory;

    @BeforeEach
    void setUp() {
        // Create a JWKSKeyLoader with the default JWKS content
        String jwksContent = JWKSFactory.createDefaultJwks();

        // Create issuer config
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .expectedClientId(CLIENT_ID)
                .jwksContent(jwksContent)
                .algorithmPreferences(new AlgorithmPreferences())
                .build();

        // Create token factory
        TokenFactoryConfig config = TokenFactoryConfig.builder().build();
        tokenFactory = new TokenFactory(config, issuerConfig);
    }

    @Test
    @DisplayName("Should count empty token events")
    void shouldCountEmptyTokenEvents() {
        // Get initial count
        long initialCount = tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY);

        // Process empty token
        tokenFactory.createAccessToken("");

        // Verify count increased
        assertEquals(initialCount + 1, tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));

        // Process another empty token
        tokenFactory.createRefreshToken("   ");

        // Verify count increased again
        assertEquals(initialCount + 2, tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
    }

    @Test
    @DisplayName("Should count failed to decode JWT events")
    void shouldCountFailedToDecodeJwtEvents() {
        // Get initial count
        long initialCount = tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT);

        // Process invalid token
        tokenFactory.createAccessToken("invalid-token");

        // Verify count increased
        assertEquals(initialCount + 1, tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT));
    }

    @Test
    @DisplayName("Should count missing claim events")
    void shouldCountMissingClaimEvents() {
        // Get initial count
        long initialCount = tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

        // Create a token without issuer
        String token = Jwts.builder()
                .subject("test-subject")
                .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                .compact();

        // Process token without issuer
        tokenFactory.createAccessToken(token);

        // Verify count increased
        assertTrue(tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.MISSING_CLAIM) > initialCount,
                "Missing claim count should increase");
    }

    @Test
    @DisplayName("Should count no issuer config events")
    void shouldCountNoIssuerConfigEvents() {
        // Get initial count
        long initialCount = tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.NO_ISSUER_CONFIG);

        // Create a token with unknown issuer
        String token = Jwts.builder()
                .issuer("https://unknown-issuer.com")
                .subject("test-subject")
                .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                .compact();

        // Process token with unknown issuer
        tokenFactory.createAccessToken(token);

        // Verify count increased
        assertEquals(initialCount + 1, tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.NO_ISSUER_CONFIG));
    }

    @Test
    @DisplayName("Should count signature validation failed events")
    void shouldCountSignatureValidationFailedEvents() {
        // Get initial count
        long initialCount = tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);

        // Create a token with invalid signature
        String validToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        String invalidToken = validToken.substring(0, validToken.lastIndexOf('.') + 1) + "invalid-signature";

        // Process token with invalid signature
        tokenFactory.createAccessToken(invalidToken);

        // Verify count increased
        assertTrue(tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED) > initialCount,
                "Signature validation failed count should increase");
    }

    @Test
    @DisplayName("Should reset security event counters")
    void shouldResetSecurityEventCounters() {
        // Generate some events
        tokenFactory.createAccessToken("");
        tokenFactory.createAccessToken("invalid-token");

        // Verify counts are non-zero
        assertTrue(tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY) > 0);
        assertTrue(tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT) > 0);

        // Reset counters
        tokenFactory.getSecurityEventCounter().reset();

        // Verify counts are zero
        assertEquals(0, tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
        assertEquals(0, tokenFactory.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT));
    }
}
