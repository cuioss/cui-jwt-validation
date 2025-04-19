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

import de.cuioss.jwt.token.JWTTokenLogMessages;
import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.claim.ClaimName;
import de.cuioss.jwt.token.domain.claim.ClaimValue;
import de.cuioss.jwt.token.domain.token.TokenContent;
import de.cuioss.jwt.token.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.token.jwks.key.KeyInfo;
import de.cuioss.jwt.token.test.generator.TokenContentImpl;
import de.cuioss.jwt.token.test.generator.ValidTokenContentGenerator;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Edge case tests for {@link TokenClaimValidator}.
 * This class focuses on testing edge cases around token expiration, clock skew,
 * and network failures.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests TokenClaimValidator edge cases")
class TokenClaimValidatorEdgeCaseTest {

    private static final String EXPECTED_AUDIENCE = "test-audience";
    private static final String EXPECTED_CLIENT_ID = "test-client-id";

    private final ValidTokenContentGenerator validTokenGenerator = new ValidTokenContentGenerator();

    @Nested
    @DisplayName("Token Expiration Edge Cases")
    class TokenExpirationEdgeCaseTests {

        @Test
        @DisplayName("Should validate token that is about to expire")
        void shouldValidateTokenThatIsAboutToExpire() {
            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token that is about to expire (5 seconds from now)
            TokenContent tokenAboutToExpire = createTokenWithExpirationTime(OffsetDateTime.now().plusSeconds(5));
            var result = validator.validate(tokenAboutToExpire);

            // Then the validation should pass
            assertTrue(result.isPresent(), "Token should be valid when about to expire but not yet expired");
        }

        @Test
        @DisplayName("Should fail validation for token that has just expired")
        void shouldFailValidationForTokenThatHasJustExpired() {
            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token that has just expired (5 seconds ago)
            TokenContent tokenJustExpired = createTokenWithExpirationTime(OffsetDateTime.now().minusSeconds(5));
            var result = validator.validate(tokenJustExpired);

            // Then the validation should fail
            assertTrue(result.isEmpty(), "Token should be invalid when just expired");

            // Verify that the appropriate warning is logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.TOKEN_EXPIRED.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("Not Before Time Edge Cases")
    class NotBeforeTimeEdgeCaseTests {

        @Test
        @DisplayName("Should validate token with not before time in the past")
        void shouldValidateTokenWithNotBeforeTimeInThePast() {
            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token with a not before time in the past
            TokenContent tokenWithPastNotBefore = createTokenWithNotBeforeTime(OffsetDateTime.now().minusMinutes(5));
            var result = validator.validate(tokenWithPastNotBefore);

            // Then the validation should pass
            assertTrue(result.isPresent(), "Token should be valid with not before time in the past");
        }

        @Test
        @DisplayName("Should validate token with not before time slightly in the future (within clock skew)")
        void shouldValidateTokenWithNotBeforeTimeSlightlyInTheFuture() {
            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token with a not before time slightly in the future (30 seconds)
            // This should be within the allowed clock skew (60 seconds)
            TokenContent tokenWithFutureNotBefore = createTokenWithNotBeforeTime(OffsetDateTime.now().plusSeconds(30));
            var result = validator.validate(tokenWithFutureNotBefore);

            // Then the validation should pass
            assertTrue(result.isPresent(), "Token should be valid with not before time slightly in the future (within clock skew)");
        }

        @Test
        @DisplayName("Should fail validation for token with not before time far in the future (beyond clock skew)")
        void shouldFailValidationForTokenWithNotBeforeTimeFarInTheFuture() {
            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token with a not before time far in the future (90 seconds)
            // This should be beyond the allowed clock skew (60 seconds)
            TokenContent tokenWithFarFutureNotBefore = createTokenWithNotBeforeTime(OffsetDateTime.now().plusSeconds(90));
            var result = validator.validate(tokenWithFarFutureNotBefore);

            // Then the validation should fail
            assertTrue(result.isEmpty(), "Token should be invalid with not before time far in the future (beyond clock skew)");

            // Verify that the appropriate warning is logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.TOKEN_NBF_FUTURE.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("Network Failure Simulation Tests")
    class NetworkFailureSimulationTests {

        @Test
        @DisplayName("Should handle network failures during key retrieval")
        void shouldHandleNetworkFailuresDuringKeyRetrieval() {
            // This test simulates a network failure during key retrieval
            // by using a JwksKeyLoader that throws an exception

            // Given an IssuerConfig with a JwksKeyLoader that simulates network failure
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .jwksLoader(new FailingJwksKeyLoader())
                    .build();

            // Create a TokenSignatureValidator with the failing JwksKeyLoader
            var signatureValidator = new TokenSignatureValidator(issuerConfig.getJwksLoader());

            // Create a valid token
            TokenContent validToken = createValidToken();
            DecodedJwt decodedJwt = ((TokenContentImpl) validToken).toDecodedJwt();

            // When validating the signature
            boolean result = signatureValidator.validateSignature(decodedJwt);

            // Then the validation should fail gracefully
            assertFalse(result, "Signature validation should fail when network error occurs");
        }
    }

    /**
     * Creates a token with a specific expiration time.
     *
     * @param expirationTime the expiration time to set
     * @return a TokenContent with the specified expiration time
     */
    private TokenContent createTokenWithExpirationTime(OffsetDateTime expirationTime) {
        // Create a valid token first
        TokenContent validToken = createValidToken();

        // Create a new claims map with the modified expiration time
        Map<String, ClaimValue> claims = new HashMap<>(validToken.getClaims());
        claims.put(ClaimName.EXPIRATION.getName(), ClaimValue.forDateTime(
                String.valueOf(expirationTime.toEpochSecond()), expirationTime));

        // Create a custom TokenContent with the modified claims
        return new CustomTokenContent(validToken, claims);
    }

    /**
     * Creates a token with a specific not before time.
     *
     * @param notBeforeTime the not before time to set
     * @return a TokenContent with the specified not before time
     */
    private TokenContent createTokenWithNotBeforeTime(OffsetDateTime notBeforeTime) {
        // Create a valid token first
        TokenContent validToken = createValidToken();

        // Create a new claims map with the added not before time
        Map<String, ClaimValue> claims = new HashMap<>(validToken.getClaims());
        claims.put(ClaimName.NOT_BEFORE.getName(), ClaimValue.forDateTime(
                String.valueOf(notBeforeTime.toEpochSecond()), notBeforeTime));

        // Create a custom TokenContent with the modified claims
        return new CustomTokenContent(validToken, claims);
    }

    /**
     * Creates a valid token for testing.
     *
     * @return a valid TokenContent
     */
    private TokenContent createValidToken() {
        // Use the ValidTokenContentGenerator to create a valid token
        return validTokenGenerator.next();
    }

    /**
     * Custom TokenContent implementation that allows overriding claims.
     */
    private static class CustomTokenContent implements TokenContent {
        private final TokenContent delegate;
        private final Map<String, ClaimValue> claims;

        public CustomTokenContent(TokenContent delegate, Map<String, ClaimValue> claims) {
            this.delegate = delegate;
            this.claims = claims;
        }

        @Override
        public Map<String, ClaimValue> getClaims() {
            return claims;
        }

        @Override
        public String getRawToken() {
            return delegate.getRawToken();
        }

        @Override
        public TokenType getTokenType() {
            return delegate.getTokenType();
        }
    }

    /**
     * JWKSKeyLoader implementation that simulates network failures.
     */
    private static class FailingJwksKeyLoader extends JWKSKeyLoader {

        /**
         * Constructor that creates a loader with empty JWKS content.
         */
        public FailingJwksKeyLoader() {
            super("{}"); // Empty JWKS content
        }

        @Override
        public Optional<KeyInfo> getKeyInfo(String kid) {
            // Simulate network failure by returning empty
            return Optional.empty();
        }

        @Override
        public Optional<KeyInfo> getFirstKeyInfo() {
            // Simulate network failure by returning empty
            return Optional.empty();
        }

        @Override
        public List<KeyInfo> getAllKeyInfos() {
            // Simulate network failure by returning empty list
            return Collections.emptyList();
        }

        @Override
        public Set<String> keySet() {
            // Simulate network failure by returning empty set
            return Collections.emptySet();
        }
    }
}
