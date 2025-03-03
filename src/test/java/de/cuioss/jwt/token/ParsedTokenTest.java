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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.OffsetDateTime;

import static de.cuioss.jwt.token.TestTokenProducer.DEFAULT_TOKEN_PARSER;
import static de.cuioss.jwt.token.TestTokenProducer.SOME_SCOPES;
import static de.cuioss.jwt.token.TestTokenProducer.validSignedJWTWithClaims;
import static de.cuioss.jwt.token.TestTokenProducer.validSignedJWTWithNotBefore;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@DisplayName("Tests ParsedToken functionality")
class ParsedTokenTest {

    private static final CuiLogger LOGGER = new CuiLogger(ParsedTokenTest.class);

    @Nested
    @DisplayName("Token Parsing ERROR Cases")
    class TokenParsingErrorTests {

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = "  ")
        @DisplayName("Should handle empty or blank token strings")
        void shouldProvideEmptyFallbackOnEmptyInput(String initialTokenString) {
            var jsonWebToken = ParsedToken.jsonWebTokenFrom(initialTokenString,
                    TestTokenProducer.DEFAULT_TOKEN_PARSER, LOGGER);
            assertFalse(jsonWebToken.isPresent(), "Token should not be present for empty input");
            LogAsserts.assertSingleLogMessagePresentContaining(TestLogLevel.WARN,
                    PortalTokenLogMessages.WARN.TOKEN_IS_EMPTY.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should handle invalid token format")
        void shouldHandleInvalidTokenFormat() {
            var initialTokenString = Generators.letterStrings(10, 20).next();

            var jsonWebToken = ParsedToken.jsonWebTokenFrom(initialTokenString,
                    TestTokenProducer.DEFAULT_TOKEN_PARSER, LOGGER);

            assertFalse(jsonWebToken.isPresent(), "Token should not be present for invalid format");
            LogAsserts.assertSingleLogMessagePresentContaining(TestLogLevel.WARN,
                    PortalTokenLogMessages.WARN.COULD_NOT_PARSE_TOKEN.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should handle invalid issuer")
        void shouldHandleInvalidIssuer() {
            var initialTokenString = validSignedJWTWithClaims(SOME_SCOPES);

            var jsonWebToken = ParsedToken
                    .jsonWebTokenFrom(initialTokenString, TestTokenProducer.WRONG_ISSUER_TOKEN_PARSER, LOGGER);

            assertFalse(jsonWebToken.isPresent(), "Token should not be present for invalid issuer");
            LogAsserts.assertSingleLogMessagePresentContaining(TestLogLevel.WARN,
                    PortalTokenLogMessages.WARN.COULD_NOT_PARSE_TOKEN.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should handle invalid signature")
        void shouldHandleInvalidSignature() {
            var initialTokenString = validSignedJWTWithClaims(SOME_SCOPES);

            var jsonWebToken = ParsedToken
                    .jsonWebTokenFrom(initialTokenString,
                            TestTokenProducer.WRONG_SIGNATURE_TOKEN_PARSER, LOGGER);
            assertFalse(jsonWebToken.isPresent(), "Token should not be present for invalid signature");
            LogAsserts.assertSingleLogMessagePresentContaining(TestLogLevel.WARN,
                    PortalTokenLogMessages.WARN.COULD_NOT_PARSE_TOKEN.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("Token Expiration Tests")
    class TokenExpirationTests {

        @Test
        @DisplayName("Should correctly handle token expiration checks")
        void shouldHandleNotExpiredToken() {
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);

            var token = ParsedAccessToken.fromTokenString(initialToken, DEFAULT_TOKEN_PARSER);
            assertTrue(token.isPresent(), "Token should be present for valid input");
            assertFalse(token.get().isExpired(), "Token should not be expired");
            assertFalse(token.get().willExpireInSeconds(5), "Token should not expire in 5 seconds");
            assertTrue(token.get().willExpireInSeconds(500), "Token should expire in 500 seconds");
        }
    }

    @Nested
    @DisplayName("Not Before Time Tests")
    class NotBeforeTimeTests {

        @Test
        @DisplayName("Should handle token without explicit nbf claim")
        void shouldHandleTokenWithoutNotBeforeClaim() {
            // Currently smallrye add nbf claim automatically
            String initialToken = validSignedJWTWithNotBefore(OffsetDateTime.now().toInstant());

            var token = ParsedAccessToken.fromTokenString(initialToken, DEFAULT_TOKEN_PARSER);
            assertTrue(token.isPresent(), "Token should be present for valid input");

            // Just verify that the method doesn't throw an exception
            // and returns something (either empty or a value)
            assertDoesNotThrow(() -> token.get().getNotBeforeTime());

        }

        @Test
        @DisplayName("Should handle token with nbf claim")
        void shouldHandleTokenWithNotBeforeClaim() {
            // Create a token with nbf set to 5 minutes ago
            java.time.Instant notBeforeTime = java.time.Instant.now().minusSeconds(300);
            String initialToken = validSignedJWTWithNotBefore(notBeforeTime);

            var token = ParsedAccessToken.fromTokenString(initialToken, DEFAULT_TOKEN_PARSER);
            assertTrue(token.isPresent(), "Token should be present for nbf in the past");
            var parsedNotBeforeTime = token.get().getNotBeforeTime();
            assertTrue(parsedNotBeforeTime.isPresent(), "Not Before Time should be present");
            assertTrue(parsedNotBeforeTime.get().isBefore(OffsetDateTime.now()), "Not Before Time should be in the past");

        }

        @Test
        @DisplayName("Should handle token with near future, less than 60 sec nbf claim")
        void shouldHandleTokenWithNearFutureNotBeforeClaim() {
            // Create a token with nbf set to 30 seconds in the future.
            // Smallrye rejects token with nbf in the future starting from 60s.
            java.time.Instant notBeforeTime = java.time.Instant.now().plusSeconds(30);
            String initialToken = validSignedJWTWithNotBefore(notBeforeTime);

            var token = ParsedAccessToken.fromTokenString(initialToken, DEFAULT_TOKEN_PARSER);
            assertTrue(token.isPresent(), "Token should be present for valid input");

            var parsedNotBeforeTime = token.get().getNotBeforeTime();
            assertTrue(parsedNotBeforeTime.isPresent(), "Not Before Time should be present");

            assertTrue(parsedNotBeforeTime.get().isAfter(OffsetDateTime.now()), "Not Before Time should be in the future");

        }

        @Test
        @DisplayName("Should handle token with future, more than 60 sec nbf claim")
        void shouldHandleTokenWithFutureNotBeforeClaim() {
            // Create a token with nbf set to 300 seconds in the future.
            // Smallrye rejects token with nbf in the future starting from 60s.
            java.time.Instant notBeforeTime = java.time.Instant.now().plusSeconds(300);
            String initialToken = validSignedJWTWithNotBefore(notBeforeTime);

            var token = ParsedAccessToken.fromTokenString(initialToken, DEFAULT_TOKEN_PARSER);
            assertFalse(token.isPresent(), "Token should not be present for valid input");

        }
    }
}
