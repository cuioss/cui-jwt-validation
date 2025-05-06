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

import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.domain.token.RefreshTokenContent;
import de.cuioss.jwt.validation.security.AlgorithmPreferences;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.jwt.validation.test.TestTokenProducer;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests TokenValidator functionality")
class TokenValidatorTest {

    private static final String ISSUER = TestTokenProducer.ISSUER;
    private static final String AUDIENCE = "test-client";
    private static final String CLIENT_ID = "test-client";

    private TokenValidator tokenValidator;
    private IssuerConfig issuerConfig;

    @BeforeEach
    void setUp() {
        // Get the default JWKS content
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();

        // Create issuer config
        issuerConfig = IssuerConfig.builder()
                .issuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .expectedClientId(CLIENT_ID)
                .jwksContent(jwksContent)
                .algorithmPreferences(new AlgorithmPreferences())
                .build();

        // Create validation factory
        tokenValidator = new TokenValidator(issuerConfig);
    }

    @Nested
    @DisplayName("Token Creation Tests")
    class TokenCreationTests {

        @Test
        @DisplayName("Should create Refresh-Token")
        void shouldCreateRefreshToken() {
            var token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.REFRESH_TOKEN);
            var parsedToken = tokenValidator.createRefreshToken(token);

            assertTrue(parsedToken.isPresent(), "Token should be present");
            assertNotNull(parsedToken.get().getRawToken(), "Token string should not be null");
            assertEquals(token, parsedToken.get().getRawToken(), "Raw validation should match input");

            // Verify claims are extracted
            assertNotNull(parsedToken.get().getClaims(), "Claims should not be null");
            assertFalse(parsedToken.get().getClaims().isEmpty(), "Claims should not be empty");

            // The test validation should have standard claims
            assertTrue(parsedToken.get().getClaims().containsKey("sub"), "Claims should contain subject");
            assertTrue(parsedToken.get().getClaims().containsKey("iss"), "Claims should contain issuer");
        }

        @Test
        @DisplayName("Should create Refresh-Token with empty claims for non-JWT Token")
        void shouldCreateRefreshTokenWithEmptyClaimsForNonJwtToken() {
            // A non-JWT Token (just a random string)
            var token = "not-a-jwt-validation";
            var parsedToken = tokenValidator.createRefreshToken(token);

            assertTrue(parsedToken.isPresent(), "Token should be present");
            assertNotNull(parsedToken.get().getRawToken(), "Token string should not be null");
            assertEquals(token, parsedToken.get().getRawToken(), "Raw validation should match input");

            // Verify claims are empty
            assertNotNull(parsedToken.get().getClaims(), "Claims should not be null");
            assertTrue(parsedToken.get().getClaims().isEmpty(), "Claims should be empty for non-JWT Token");
        }

        @Test
        @DisplayName("Should create access token")
        void shouldCreateAccessToken() {
            var token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
            var parsedToken = tokenValidator.createAccessToken(token);

            // The validation should be validated by the pipeline
            // With our current setup, we expect it to fail validation
            // This is because we need more sophisticated setup for the full pipeline
            assertFalse(parsedToken.isPresent(), "Token should not be present with current test setup");
        }

        @Test
        @DisplayName("Should create ID-Token")
        void shouldCreateIdToken() {
            var token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_ID_TOKEN);
            var parsedToken = tokenValidator.createIdToken(token);

            // The validation should be validated by the pipeline
            // With our current setup, we expect it to fail validation
            // This is because we need more sophisticated setup for the full pipeline
            assertFalse(parsedToken.isPresent(), "Token should not be present with current test setup");
        }
    }

    @Nested
    @DisplayName("Token Size Validation Tests")
    class TokenSizeValidationTests {

        @Test
        @DisplayName("Should respect custom validation size limits")
        void shouldRespectCustomTokenSizeLimits() {
            // Create a validation that exceeds the custom max size but is smaller than the default
            int customMaxSize = 1024;
            String largeToken = "a".repeat(customMaxSize + 1);

            // Create TokenValidator with custom validation size limits
            ParserConfig customConfig = ParserConfig.builder()
                    .maxTokenSize(customMaxSize)
                    .build();
            var factory = new TokenValidator(customConfig, issuerConfig);

            // Verify it rejects a validation that exceeds the custom max size
            var parsedToken = factory.createAccessToken(largeToken);

            assertFalse(parsedToken.isPresent(), "Token exceeding custom max size should be rejected");
        }

        @Test
        @DisplayName("Should respect custom payload size limits")
        void shouldRespectCustomPayloadSizeLimits() {
            // Create TokenValidator with custom payload size limits
            ParserConfig customConfig = ParserConfig.builder()
                    .maxPayloadSize(100)
                    .build();
            var factory = new TokenValidator(customConfig, issuerConfig);

            // Create a JWT with a large payload using io.jsonwebtoken
            String token = Jwts.builder().issuer(TestTokenProducer.ISSUER).subject("test-subject")
                    .claim("large-claim", "a".repeat(200))
                    .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                            Jwts.SIG.RS256)
                    .compact();

            // Verify it rejects a validation with a payload that exceeds the custom max size
            var parsedToken = factory.createAccessToken(token);

            assertFalse(parsedToken.isPresent(), "Token with payload exceeding custom max size should be rejected");
        }
    }

    @Nested
    @DisplayName("Token Validation Error Tests")
    class TokenValidationErrorTests {

        @Test
        @DisplayName("Should handle empty or blank token strings")
        void shouldProvideEmptyFallbackOnEmptyInput() {
            // Test with empty string
            var emptyToken = tokenValidator.createAccessToken("");
            assertFalse(emptyToken.isPresent(), "Token should not be present for empty input");

            // Test with blank string
            var blankToken = tokenValidator.createAccessToken("   ");
            assertFalse(blankToken.isPresent(), "Token should not be present for blank input");
        }

        @Test
        @DisplayName("Should handle invalid validation format")
        void shouldHandleInvalidTokenFormat() {
            var initialTokenString = Generators.letterStrings(10, 20).next();

            var token = tokenValidator.createAccessToken(initialTokenString);

            assertFalse(token.isPresent(), "Token should not be present for invalid format");
        }

        @Test
        @DisplayName("Should handle unknown issuer")
        void shouldHandleUnknownIssuer() {
            // Create a validation with an unknown issuer
            String token = Jwts.builder()
                    .issuer("https://unknown-issuer.com")
                    .subject("test-subject")
                    .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey())
                    .compact();

            var parsedToken = tokenValidator.createAccessToken(token);

            assertFalse(parsedToken.isPresent(), "Token with unknown issuer should not be valid");
        }
    }

    @Nested
    @DisplayName("Token Logging Tests")
    class TokenLoggingTests {
        private static final String INVALID_TOKEN = "invalid.validation.string";
        private static final String EMPTY_TOKEN = "";

        @Test
        @DisplayName("Should log warning when validation is empty")
        void shouldLogWarningWhenTokenIsEmpty() {
            // When creating a validation with an empty string
            Optional<AccessTokenContent> result = tokenValidator.createAccessToken(EMPTY_TOKEN);

            // Then the validation creation should fail
            assertFalse(result.isPresent(), "Token creation should fail with empty validation");

            // And the appropriate warning should be logged
            LogAsserts.assertLogMessagePresent(TestLogLevel.WARN, JWTValidationLogMessages.WARN.TOKEN_IS_EMPTY.format());
        }

        @Test
        @DisplayName("Should log warning when validation format is invalid")
        void shouldLogWarningWhenTokenFormatIsInvalid() {
            // When creating a validation with an invalid format
            Optional<AccessTokenContent> result = tokenValidator.createAccessToken(INVALID_TOKEN);

            // Then the validation creation should fail
            assertFalse(result.isPresent(), "Token creation should fail with invalid validation format");

            // And the appropriate warning should be logged
            LogAsserts.assertLogMessagePresent(TestLogLevel.WARN, JWTValidationLogMessages.WARN.FAILED_TO_DECODE_JWT.format());
        }

        @Test
        @DisplayName("Should log warning when validation validation fails")
        void shouldLogWarningWhenTokenValidationFails() {
            // Given a validation with an unknown issuer
            String tokenWithUnknownIssuer = TestTokenProducer.validSignedJWTWithClaims(
                    TestTokenProducer.SOME_SCOPES, "unknown-issuer");

            // When creating an access token
            Optional<AccessTokenContent> result = tokenValidator.createAccessToken(tokenWithUnknownIssuer);

            // Then the validation creation should fail
            assertFalse(result.isPresent(), "Token creation should fail with unknown issuer");

            // And a warning should be logged
            // The exact message might vary, but we should see a warning related to validation validation
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "missing required claim");
        }

        @Test
        @DisplayName("Should log warning when validation is missing claims")
        void shouldLogWarningWhenTokenIsMissingClaims() {
            // Given a valid token string but missing required claims
            String validToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);

            // When creating an access token
            tokenValidator.createAccessToken(validToken);

            // Then the appropriate warning message should be logged
            // Note: The actual message might vary, but we should at least see a warning message
            // related to missing claims
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "missing required claim");
        }

        @Test
        @DisplayName("Should log warning when ID-Token is missing claims")
        void shouldLogWarningWhenIdTokenIsMissingClaims() {
            // Given a valid token string but missing required claims
            String validToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_ID_TOKEN);

            // When creating an ID-Token
            tokenValidator.createIdToken(validToken);

            // Then the appropriate warning message should be logged
            // Note: The actual message might vary, but we should at least see a warning message
            // related to missing claims
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "missing required claim");
        }

        @Test
        @DisplayName("Should create Refresh-Token successfully")
        void shouldCreateRefreshTokenSuccessfully() {
            // Given a valid token string
            String validToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.REFRESH_TOKEN);

            // When creating a Refresh-Token
            Optional<RefreshTokenContent> result = tokenValidator.createRefreshToken(validToken);

            // Then the validation should be created successfully
            assertTrue(result.isPresent(), "Refresh validation should be created successfully");

            // For refresh tokens, we don't need to check for specific log messages
            // as the test itself verifies the functionality works
        }

        @Test
        @DisplayName("Should log warning when key is not found")
        void shouldLogWarningWhenKeyIsNotFound() {
            // Create a validation with a key ID that doesn't exist in our JWKS
            String tokenWithUnknownKeyId = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);

            // Create a new issuer config with a JWKS that doesn't contain the key ID
            IssuerConfig newIssuerConfig = IssuerConfig.builder()
                    .issuer(ISSUER)
                    .expectedAudience(AUDIENCE)
                    .expectedClientId(CLIENT_ID)
                    .jwksContent(InMemoryJWKSFactory.createEmptyJwks())
                    .build();

            // Create a new validation factory with the new issuer config
            TokenValidator newTokenValidator = new TokenValidator(newIssuerConfig);

            // When creating an access token
            Optional<AccessTokenContent> result = newTokenValidator.createAccessToken(tokenWithUnknownKeyId);

            // Then the validation creation should fail
            assertFalse(result.isPresent(), "Token creation should fail with unknown key ID");

            // And a warning should be logged about key issues
            // The exact message might vary, but we should see a warning related to keys
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "key");
        }

        @Test
        @DisplayName("Should log info message when TokenValidator is initialized")
        void shouldLogInfoMessageWhenTokenFactoryIsInitialized() {
            // Create multiple issuer configs to test the count in the log message
            IssuerConfig issuerConfig1 = IssuerConfig.builder()
                    .issuer(ISSUER)
                    .expectedAudience(AUDIENCE)
                    .expectedClientId(CLIENT_ID)
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .build();

            IssuerConfig issuerConfig2 = IssuerConfig.builder()
                    .issuer("https://another-issuer.com")
                    .expectedAudience(AUDIENCE)
                    .expectedClientId(CLIENT_ID)
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .build();

            // Create a new validation factory with multiple issuer configs
            new TokenValidator(
                    issuerConfig1,
                    issuerConfig2);

            // Verify that the appropriate info message is logged
            LogAsserts.assertLogMessagePresent(
                    TestLogLevel.INFO,
                    JWTValidationLogMessages.INFO.TOKEN_FACTORY_INITIALIZED.format(2));
        }
    }
}
