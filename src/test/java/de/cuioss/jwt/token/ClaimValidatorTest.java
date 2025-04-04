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

import de.cuioss.jwt.token.test.KeyMaterialHandler;
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
import java.util.HashSet;
import java.util.Set;

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
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token from64EncodedContent issuer");
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

    @Test
    @DisplayName("Should validate token with matching audience (string format)")
    void shouldValidateTokenWithMatchingAudienceString() {
        // Given a token with audience claim as a string
        String expectedAudience = "test-audience";
        String token = TestTokenProducer.validSignedJWTWithAudience(new String[]{expectedAudience}, false);
        Jws<Claims> jws = parseToken(token);

        // Create a validator with the expected audience
        Set<String> expectedAudienceSet = Set.of(expectedAudience);
        ClaimValidator audienceValidator = new ClaimValidator(EXPECTED_ISSUER, expectedAudienceSet);

        // When validating the claims
        boolean result = audienceValidator.validateClaims(jws);

        // Then the validation should pass
        assertTrue(result, "Token with matching audience (string format) should be valid");
    }

    @Test
    @DisplayName("Should validate token with matching audience (array format)")
    void shouldValidateTokenWithMatchingAudienceArray() {
        // Given a token with audience claim as an array
        String[] audienceArray = {"audience1", "test-audience", "audience3"};
        String token = TestTokenProducer.validSignedJWTWithAudience(audienceArray, true);
        Jws<Claims> jws = parseToken(token);

        // Create a validator with the expected audience
        Set<String> expectedAudienceSet = Set.of("test-audience");
        ClaimValidator audienceValidator = new ClaimValidator(EXPECTED_ISSUER, expectedAudienceSet);

        // When validating the claims
        boolean result = audienceValidator.validateClaims(jws);

        // Then the validation should pass
        assertTrue(result, "Token with matching audience (array format) should be valid");
    }

    @Test
    @DisplayName("Should reject token with non-matching audience")
    void shouldRejectTokenWithNonMatchingAudience() {
        // Given a token with audience claim that doesn't match the expected audience
        String token = TestTokenProducer.validSignedJWTWithAudience(new String[]{"wrong-audience"}, false);
        Jws<Claims> jws = parseToken(token);

        // Create a validator with a different expected audience
        Set<String> expectedAudienceSet = Set.of("test-audience");
        ClaimValidator audienceValidator = new ClaimValidator(EXPECTED_ISSUER, expectedAudienceSet);

        // When validating the claims
        boolean result = audienceValidator.validateClaims(jws);

        // Then the validation should fail
        assertFalse(result, "Token with non-matching audience should be invalid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token audience");
    }

    @Test
    @DisplayName("Should reject token without audience claim when expected audience is provided")
    void shouldRejectTokenWithoutAudienceWhenExpected() {
        // Given a token without audience claim
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        Jws<Claims> jws = parseToken(token);

        // Create a validator with an expected audience
        Set<String> expectedAudienceSet = Set.of("test-audience");
        ClaimValidator audienceValidator = new ClaimValidator(EXPECTED_ISSUER, expectedAudienceSet);

        // When validating the claims
        boolean result = audienceValidator.validateClaims(jws);

        // Then the validation should fail
        assertFalse(result, "Token without audience claim should be invalid when expected audience is provided");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.MISSING_CLAIM.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should validate token without audience claim when no expected audience is provided")
    void shouldValidateTokenWithoutAudienceWhenNotExpected() {
        // Given a token without audience claim
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        Jws<Claims> jws = parseToken(token);

        // When validating the claims with the default validator (no expected audience)
        boolean result = validator.validateClaims(jws);

        // Then the validation should pass
        assertTrue(result, "Token without audience claim should be valid when no expected audience is provided");
    }

    @Test
    @DisplayName("Should validate token with multiple expected audiences")
    void shouldValidateTokenWithMultipleExpectedAudiences() {
        // Given a token with audience claim
        String token = TestTokenProducer.validSignedJWTWithAudience(new String[]{"audience1"}, false);
        Jws<Claims> jws = parseToken(token);

        // Create a validator with multiple expected audiences
        Set<String> expectedAudienceSet = new HashSet<>();
        expectedAudienceSet.add("test-audience");
        expectedAudienceSet.add("audience1");
        expectedAudienceSet.add("audience3");
        ClaimValidator audienceValidator = new ClaimValidator(EXPECTED_ISSUER, expectedAudienceSet);

        // When validating the claims
        boolean result = audienceValidator.validateClaims(jws);

        // Then the validation should pass
        assertTrue(result, "Token with audience matching one of multiple expected audiences should be valid");
    }

    /**
     * Helper method to parse a token string into a Jws<ClaimNames> object.
     * This method disables expiration validation in the JJWT parser so we can test
     * the ClaimValidator's expiration validation separately.
     */
    private Jws<Claims> parseToken(String token) {
        return Jwts.parser()
                .verifyWith(KeyMaterialHandler.getDefaultPublicKey())
                .clockSkewSeconds(Integer.MAX_VALUE) // Disable expiration validation
                .build()
                .parseSignedClaims(token);
    }
}
