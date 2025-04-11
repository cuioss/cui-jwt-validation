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

import de.cuioss.jwt.token.security.AlgorithmPreferences;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.json.Json;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenHeaderValidator}.
 */
@EnableTestLogger(debug = TokenHeaderValidator.class, warn = TokenHeaderValidator.class)
@DisplayName("Tests TokenHeaderValidator functionality")
class TokenHeaderValidatorTest {

    private static final String EXPECTED_ISSUER = TestTokenProducer.ISSUER;
    private static final String WRONG_ISSUER = TestTokenProducer.WRONG_ISSUER;
    private static final NonValidatingJwtParser JWT_PARSER = NonValidatingJwtParser.builder().build();

    @Nested
    @DisplayName("Builder Configuration Tests")
    class BuilderConfigurationTests {

        @Test
        @DisplayName("Should create validator with expected issuer")
        void shouldCreateValidatorWithExpectedIssuer() {
            // Given a builder with expected issuer
            var builder = TokenHeaderValidator.builder()
                    .expectedIssuer(EXPECTED_ISSUER);

            // When building the validator
            TokenHeaderValidator validator = builder.build();

            // Then the validator should be created without warnings
            assertNotNull(validator, "Validator should not be null");
            assertFalse(validator.getExpectedIssuer().isEmpty(), "Expected issuer should not be empty");
            assertTrue(validator.getExpectedIssuer().contains(EXPECTED_ISSUER), "Expected issuer should contain the configured value");
            assertNotNull(validator.getAlgorithmPreferences(), "Algorithm preferences should not be null");
        }

        @Test
        @DisplayName("Should create validator with expected issuer set")
        void shouldCreateValidatorWithExpectedIssuerSet() {
            // Given a builder with expected issuer as a set
            var builder = TokenHeaderValidator.builder()
                    .expectedIssuer(Set.of(EXPECTED_ISSUER));

            // When building the validator
            TokenHeaderValidator validator = builder.build();

            // Then the validator should be created without warnings
            assertNotNull(validator, "Validator should not be null");
            assertFalse(validator.getExpectedIssuer().isEmpty(), "Expected issuer should not be empty");
            assertTrue(validator.getExpectedIssuer().contains(EXPECTED_ISSUER), "Expected issuer should contain the configured value");
        }

        @Test
        @DisplayName("Should create validator with custom algorithm preferences")
        void shouldCreateValidatorWithCustomAlgorithmPreferences() {
            // Given a builder with custom algorithm preferences
            var customAlgorithmPreferences = new AlgorithmPreferences(List.of("RS256", "ES256"));
            var builder = TokenHeaderValidator.builder()
                    .expectedIssuer(EXPECTED_ISSUER)
                    .algorithmPreferences(customAlgorithmPreferences);

            // When building the validator
            TokenHeaderValidator validator = builder.build();

            // Then the validator should be created with the custom algorithm preferences
            assertNotNull(validator, "Validator should not be null");
            assertSame(customAlgorithmPreferences, validator.getAlgorithmPreferences(), "Algorithm preferences should be the same instance");
        }

        @Test
        @DisplayName("Should throw exception when missing expected issuer")
        void shouldThrowExceptionWhenMissingExpectedIssuer() {
            // Given a builder without expected issuer
            var builder = TokenHeaderValidator.builder();

            // When building the validator, then an exception should be thrown
            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    builder::build,
                    "Should throw IllegalArgumentException when no expectedIssuer is provided"
            );

            // Verify the exception message
            assertTrue(exception.getMessage().contains("At least one expectedIssuer must be provided"),
                    "Exception message should mention that at least one expectedIssuer is required");
        }

        @Test
        @DisplayName("Should use default algorithm preferences when not specified")
        void shouldUseDefaultAlgorithmPreferencesWhenNotSpecified() {
            // Given a builder without algorithm preferences
            var builder = TokenHeaderValidator.builder()
                    .expectedIssuer(EXPECTED_ISSUER);

            // When building the validator
            TokenHeaderValidator validator = builder.build();

            // Then the validator should use default algorithm preferences
            assertNotNull(validator, "Validator should not be null");
            assertNotNull(validator.getAlgorithmPreferences(), "Algorithm preferences should not be null");
            assertEquals(AlgorithmPreferences.getDefaultPreferredAlgorithms(),
                    validator.getAlgorithmPreferences().getPreferredAlgorithms(),
                    "Should use default algorithm preferences");
        }
    }

    @Nested
    @DisplayName("Algorithm Validation Tests")
    class AlgorithmValidationTests {

        @Test
        @DisplayName("Should validate token with supported algorithm")
        void shouldValidateTokenWithSupportedAlgorithm() {
            // Given a validator with default algorithm preferences
            TokenHeaderValidator validator = TokenHeaderValidator.builder()
                    .expectedIssuer(EXPECTED_ISSUER)
                    .build();

            // And a token with a supported algorithm (RS256)
            String token = TestTokenProducer.validSignedEmptyJWT();
            Optional<DecodedJwt> decodedJwt = JWT_PARSER.decode(token);
            assertTrue(decodedJwt.isPresent(), "Token should be decoded successfully");

            // When validating the token
            boolean isValid = validator.validate(decodedJwt.get());

            // Then the validation should pass
            assertTrue(isValid, "Token with supported algorithm should be valid");
        }

        @Test
        @DisplayName("Should reject token with unsupported algorithm")
        void shouldRejectTokenWithUnsupportedAlgorithm() {
            // Given a validator with custom algorithm preferences that only support ES256
            TokenHeaderValidator validator = TokenHeaderValidator.builder()
                    .expectedIssuer(EXPECTED_ISSUER)
                    .algorithmPreferences(new AlgorithmPreferences(List.of("ES256")))
                    .build();

            // And a token with an unsupported algorithm (RS256)
            String token = TestTokenProducer.validSignedEmptyJWT();
            Optional<DecodedJwt> decodedJwt = JWT_PARSER.decode(token);
            assertTrue(decodedJwt.isPresent(), "Token should be decoded successfully");
            assertEquals("RS256", decodedJwt.get().getAlg().orElse(null), "Token should use RS256 algorithm");

            // When validating the token
            boolean isValid = validator.validate(decodedJwt.get());

            // Then the validation should fail
            assertFalse(isValid, "Token with unsupported algorithm should be invalid");

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Unsupported algorithm: RS256");
        }

        @Test
        @DisplayName("Should reject token with missing algorithm")
        void shouldRejectTokenWithMissingAlgorithm() {
            // Given a validator
            TokenHeaderValidator validator = TokenHeaderValidator.builder()
                    .expectedIssuer(EXPECTED_ISSUER)
                    .build();

            // And a token with a missing algorithm (mocked)
            DecodedJwt decodedJwt = new DecodedJwt(null, null, null, new String[]{"", "", ""}, "");

            // When validating the token
            boolean isValid = validator.validate(decodedJwt);

            // Then the validation should fail
            assertFalse(isValid, "Token with missing algorithm should be invalid");

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token is missing required claim: alg");
        }
    }

    @Nested
    @DisplayName("Issuer Validation Tests")
    class IssuerValidationTests {

        @Test
        @DisplayName("Should validate token with expected issuer")
        void shouldValidateTokenWithExpectedIssuer() {
            // Given a validator with expected issuer
            TokenHeaderValidator validator = TokenHeaderValidator.builder()
                    .expectedIssuer(EXPECTED_ISSUER)
                    .build();

            // And a token with the expected issuer
            String token = TestTokenProducer.validSignedEmptyJWT();
            Optional<DecodedJwt> decodedJwt = JWT_PARSER.decode(token);
            assertTrue(decodedJwt.isPresent(), "Token should be decoded successfully");
            assertEquals(EXPECTED_ISSUER, decodedJwt.get().getIssuer().orElse(null), "Token should have expected issuer");

            // When validating the token
            boolean isValid = validator.validate(decodedJwt.get());

            // Then the validation should pass
            assertTrue(isValid, "Token with expected issuer should be valid");
        }

        @Test
        @DisplayName("Should reject token with wrong issuer")
        void shouldRejectTokenWithWrongIssuer() {
            // Given a validator with expected issuer
            TokenHeaderValidator validator = TokenHeaderValidator.builder()
                    .expectedIssuer(EXPECTED_ISSUER)
                    .build();

            // And a token with a wrong issuer (mocked)
            DecodedJwt decodedJwt = new DecodedJwt(
                    Json.createObjectBuilder().add("alg", "RS256").build(),
                    Json.createObjectBuilder().add("iss", WRONG_ISSUER).build(),
                    null,
                    new String[]{"", "", ""},
                    "");

            // When validating the token
            boolean isValid = validator.validate(decodedJwt);

            // Then the validation should fail
            assertFalse(isValid, "Token with wrong issuer should be invalid");

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    "Token issuer '" + WRONG_ISSUER + "' does not match expected issuer");
        }

        @Test
        @DisplayName("Should reject token with missing issuer")
        void shouldRejectTokenWithMissingIssuer() {
            // Given a validator with expected issuer
            TokenHeaderValidator validator = TokenHeaderValidator.builder()
                    .expectedIssuer(EXPECTED_ISSUER)
                    .build();

            // And a token with a missing issuer (mocked)
            DecodedJwt decodedJwt = new DecodedJwt(
                    Json.createObjectBuilder().add("alg", "RS256").build(),
                    Json.createObjectBuilder().build(),
                    null,
                    new String[]{"", "", ""},
                    "");

            // When validating the token
            boolean isValid = validator.validate(decodedJwt);

            // Then the validation should fail
            assertFalse(isValid, "Token with missing issuer should be invalid");

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token is missing required claim: iss");
        }

        @Test
        @DisplayName("Should validate issuer when expected issuer is configured")
        void shouldValidateIssuerWhenExpectedIssuerIsConfigured() {
            // Given a validator with an expected issuer that doesn't match the token's issuer
            TokenHeaderValidator validator = TokenHeaderValidator.builder()
                    .expectedIssuer("dummy-issuer")
                    .build();

            // And a token with a different issuer
            String token = TestTokenProducer.validSignedEmptyJWT();
            Optional<DecodedJwt> decodedJwt = JWT_PARSER.decode(token);
            assertTrue(decodedJwt.isPresent(), "Token should be decoded successfully");
            assertEquals(EXPECTED_ISSUER, decodedJwt.get().getIssuer().orElse(null), "Token should have expected issuer");

            // When validating the token
            boolean isValid = validator.validate(decodedJwt.get());

            // Then the validation should fail (issuer validation fails)
            assertFalse(isValid, "Validation should fail when token issuer doesn't match expected issuer");

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    "Token issuer '" + EXPECTED_ISSUER + "' does not match expected issuer");
        }
    }
}
