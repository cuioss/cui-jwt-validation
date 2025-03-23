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

import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link ClaimValidator} to verify it doesn't duplicate validation on other types.
 */
@EnableTestLogger(debug = ClaimValidator.class, warn = ClaimValidator.class)
@DisplayName("Tests ClaimValidator functionality")
class ClaimValidatorTest {

    private ClaimValidator validator;
    private static final String EXPECTED_ISSUER = TestTokenProducer.ISSUER;
    private static final String WRONG_ISSUER = TestTokenProducer.WRONG_ISSUER;

    @BeforeEach
    void setUp() {
        validator = new ClaimValidator(EXPECTED_ISSUER);
    }

    @Test
    @DisplayName("Should validate token with all required claims")
    void shouldValidateTokenWithAllRequiredClaims() {
        // Given a token with all required claims
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        Jws<Claims> jws = parseToken(token);

        // When validating the claims
        boolean result = validator.validateClaims(jws);

        // Then the validation should pass
        assertTrue(result, "Token with all required claims should be valid");
    }

    @Test
    @DisplayName("Should reject token with wrong issuer")
    void shouldRejectTokenWithWrongIssuer() {
        // Given a token with wrong issuer
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        Jws<Claims> jws = parseToken(token);

        // Create a validator with a different expected issuer
        ClaimValidator wrongIssuerValidator = new ClaimValidator(WRONG_ISSUER);

        // When validating the claims
        boolean result = wrongIssuerValidator.validateClaims(jws);

        // Then the validation should fail
        assertFalse(result, "Token with wrong issuer should be invalid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token issuer");
    }

    @Test
    @DisplayName("Should reject expired token")
    void shouldRejectExpiredToken() {
        // Given an expired token
        Instant expiredTime = Instant.now().minus(1, ChronoUnit.HOURS);
        String token = TestTokenProducer.validSignedJWTExpireAt(expiredTime);
        Jws<Claims> jws = parseToken(token);

        // When validating the claims
        boolean result = validator.validateClaims(jws);

        // Then the validation should fail
        assertFalse(result, "Expired token should be invalid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token from issuer");
    }

    @Test
    @DisplayName("Should validate different token types without duplication")
    void shouldValidateDifferentTokenTypesWithoutDuplication() {
        // Given tokens of different types
        String accessToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        String idToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_ID_TOKEN);

        Jws<Claims> accessJws = parseToken(accessToken);
        Jws<Claims> idJws = parseToken(idToken);

        // When validating the claims for different token types
        boolean accessResult = validator.validateClaims(accessJws);
        boolean idResult = validator.validateClaims(idJws);

        // Then the validation should pass for both token types
        assertTrue(accessResult, "Access token should be valid");
        assertTrue(idResult, "ID token should be valid");
    }

    @Test
    @DisplayName("Should accept token without nbf claim")
    void shouldAcceptTokenWithoutNbfClaim() {
        // Given a token without nbf claim
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        Jws<Claims> jws = parseToken(token);

        // When validating the claims
        boolean result = validator.validateClaims(jws);

        // Then the validation should pass
        assertTrue(result, "Token without nbf claim should be valid");
    }

    @Test
    @DisplayName("Should accept token with nbf claim in the past")
    void shouldAcceptTokenWithNbfClaimInPast() {
        // Given a token with nbf claim in the past
        Instant pastTime = Instant.now().minus(1, ChronoUnit.HOURS);
        String token = TestTokenProducer.validSignedJWTWithNotBefore(pastTime);
        Jws<Claims> jws = parseToken(token);

        // When validating the claims
        boolean result = validator.validateClaims(jws);

        // Then the validation should pass
        assertTrue(result, "Token with nbf claim in the past should be valid");
    }

    @Test
    @DisplayName("Should accept token with nbf claim in the future but within leeway")
    void shouldAcceptTokenWithNbfClaimInFutureWithinLeeway() {
        // Given a token with nbf claim in the future but within 60-second leeway
        Instant futureTimeWithinLeeway = Instant.now().plus(30, ChronoUnit.SECONDS);
        String token = TestTokenProducer.validSignedJWTWithNotBefore(futureTimeWithinLeeway);
        Jws<Claims> jws = parseToken(token);

        // When validating the claims
        boolean result = validator.validateClaims(jws);

        // Then the validation should pass
        assertTrue(result, "Token with nbf claim in the future but within leeway should be valid");
    }

    @Test
    @DisplayName("Should reject token with nbf claim too far in the future")
    void shouldRejectTokenWithNbfClaimTooFarInFuture() {
        // Given a token with nbf claim more than 60 seconds in the future
        Instant futureTimeBeyondLeeway = Instant.now().plus(120, ChronoUnit.SECONDS);
        String token = TestTokenProducer.validSignedJWTWithNotBefore(futureTimeBeyondLeeway);
        Jws<Claims> jws = parseToken(token);

        // When validating the claims
        boolean result = validator.validateClaims(jws);

        // Then the validation should fail
        assertFalse(result, "Token with nbf claim too far in the future should be invalid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token has a 'not before' claim that is more than 60 seconds in the future");
    }

    /**
     * Helper method to parse a token string into a Jws<Claims> object.
     * This method disables expiration validation in the JJWT parser so we can test
     * the ClaimValidator's expiration validation separately.
     */
    private Jws<Claims> parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(de.cuioss.jwt.token.test.KeyMaterialHandler.getDefaultPrivateKey())
                .setAllowedClockSkewSeconds(Integer.MAX_VALUE) // Disable expiration validation
                .build()
                .parseClaimsJws(token);
    }
}
