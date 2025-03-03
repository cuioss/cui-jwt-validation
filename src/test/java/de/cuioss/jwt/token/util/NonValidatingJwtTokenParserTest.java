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
package de.cuioss.jwt.token.util;

import de.cuioss.jwt.token.PortalTokenLogMessages;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.string.MoreStrings;
import de.cuioss.tools.string.Splitter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static de.cuioss.jwt.token.TestTokenProducer.*;
import static de.cuioss.test.juli.LogAsserts.assertLogMessagePresentContaining;
import static de.cuioss.test.juli.LogAsserts.assertNoLogMessagePresent;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger(debug = NonValidatingJwtTokenParser.class)
@DisplayName("Tests NonValidatingJwtTokenParser functionality")
class NonValidatingJwtTokenParserTest {

    private NonValidatingJwtTokenParser parser;

    @BeforeEach
    void setUp() {
        parser = new NonValidatingJwtTokenParser();
    }

    @Nested
    @DisplayName("Valid Token Tests")
    class ValidTokenTests {

        @Test
        @DisplayName("Should parse valid token with scopes")
        void shouldParseValidToken() {
            var token = validSignedJWTWithClaims(SOME_SCOPES);
            var result = parser.unsecured(token);

            assertTrue(result.isPresent(), "Result should be present for valid token");
            var jwt = result.get();
            assertEquals(ISSUER, jwt.getIssuer(), "Issuer should match");
            assertNotNull(jwt.getSubject(), "Subject should not be null");
            assertNotNull(jwt.getTokenID(), "Token ID should not be null");
            assertTrue(jwt.getExpirationTime() > 0, "Expiration time should be positive");
            assertTrue(jwt.getIssuedAtTime() > 0, "Issued at time should be positive");
            assertTrue(jwt.getGroups().isEmpty(), "Groups should be empty");
            assertTrue(jwt.getAudience().isEmpty(), "Audience should be empty");
            assertTrue(jwt.getClaimNames().size() > 5, "Should have more than 5 claims");
            assertNull(jwt.getRawToken(), "Raw token should be null");
            assertNoLogMessagePresent(TestLogLevel.WARN, NonValidatingJwtTokenParser.class);
            assertNoLogMessagePresent(TestLogLevel.ERROR, NonValidatingJwtTokenParser.class);
        }

        @Test
        @DisplayName("Should parse token with name claim")
        void shouldParseTokenWithName() {
            var token = validSignedJWTWithClaims(SOME_NAME);
            var result = parser.unsecured(token);

            assertTrue(result.isPresent(), "Result should be present for valid token");
            var jwt = result.get();
            assertNotNull(jwt.getName(), "Name should not be null");
            assertNoLogMessagePresent(TestLogLevel.WARN, NonValidatingJwtTokenParser.class);
            assertNoLogMessagePresent(TestLogLevel.ERROR, NonValidatingJwtTokenParser.class);
        }

        @Test
        @DisplayName("Should handle token with minimal claims")
        void shouldHandleEmptyToken() {
            var token = createTokenWithLargePayload(1);
            var result = parser.unsecured(token);
            assertTrue(result.isPresent(), "Result should be present for minimal token");
            var jwt = result.get();
            assertEquals(0, jwt.getExpirationTime(), "Expiration time should be 0");
            assertEquals(0, jwt.getIssuedAtTime(), "Issued at time should be 0");
        }
    }

    @Nested
    @DisplayName("Invalid Token Format Tests")
    @EnableTestLogger(debug = NonValidatingJwtTokenParser.class)
    class InvalidTokenFormatTests {

        @ParameterizedTest(name = "Should handle invalid token format: {0}")
        @CsvSource({
                "not.a.jwt, Failed to parse token",
                "'', Token is empty or null",
                "before.after, Invalid JWT token format: expected 3 parts but got 2",
                "before.after.that.else, Invalid JWT token format: expected 3 parts but got 4",
                "invalid, Invalid JWT token format: expected 3 parts but got 1"
        })
        @DisplayName("Should handle various invalid token formats")
        void shouldHandleInvalidTokenFormat(String invalidToken, String expectedMessage) {
            var result = parser.unsecured(invalidToken);
            assertTrue(result.isEmpty(), "Result should be empty for invalid token");
            if ("not.a.jwt".equals(invalidToken)) {
                assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Failed to parse token");
            } else if (MoreStrings.isEmpty(invalidToken)) {
                assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Token is empty or null");
            } else {
                assertLogMessagePresentContaining(TestLogLevel.DEBUG,
                        "Invalid JWT token format: expected 3 parts but got %d".formatted(
                                Splitter.on('.').splitToList(invalidToken).size()));
            }
        }

        @Test
        @DisplayName("Should handle null token")
        void shouldHandleNullToken() {
            var result = parser.unsecured(null);
            assertTrue(result.isEmpty(), "Result should be empty for null token");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Token is empty or null");
        }
    }

    @Nested
    @DisplayName("Token Size Limit Tests")
    class TokenSizeLimitTests {

        @ParameterizedTest(name = "Should reject token of size {0}KB")
        @ValueSource(ints = {9, 10, 12, 16})
        @DisplayName("Should reject oversized tokens")
        void shouldRejectOversizedToken(int sizeInKb) {
            String largeToken = createLargeToken(sizeInKb);
            var result = parser.unsecured(largeToken);
            assertTrue(result.isEmpty(), "Result should be empty for oversized token");
            assertLogMessagePresentContaining(TestLogLevel.WARN,
                    PortalTokenLogMessages.WARN.TOKEN_SIZE_EXCEEDED.resolveIdentifierString());
        }

        @ParameterizedTest(name = "Should reject payload of size {0}KB")
        @ValueSource(ints = {17, 20, 24, 32})
        @DisplayName("Should reject tokens with oversized payload")
        void shouldRejectLargePayload(int sizeInKb) {
            String tokenWithLargePayload = createTokenWithLargePayload(sizeInKb);
            var result = parser.unsecured(tokenWithLargePayload);
            assertTrue(result.isEmpty(), "Result should be empty for token with oversized payload");
            assertLogMessagePresentContaining(TestLogLevel.WARN,
                    PortalTokenLogMessages.WARN.TOKEN_SIZE_EXCEEDED.resolveIdentifierString());
        }
    }

    private String createLargeToken(int sizeInKb) {
        String repeatedChar = IntStream.range(0, sizeInKb * 1024)
                .mapToObj(i -> "a")
                .collect(Collectors.joining());
        return repeatedChar + "." + repeatedChar + "." + repeatedChar;
    }

    private String createTokenWithLargePayload(int sizeInKb) {
        // Create a valid header
        String header = Base64.getUrlEncoder().encodeToString(
                "{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));

        // Create a large payload
        String largeJson = "{\"data\":\"" +
                IntStream.range(0, sizeInKb * 1024)
                        .mapToObj(i -> "a")
                        .collect(Collectors.joining()) +
                "\"}";
        String payload = Base64.getUrlEncoder().encodeToString(
                largeJson.getBytes(StandardCharsets.UTF_8));

        // Add a dummy signature
        String signature = Base64.getUrlEncoder().encodeToString("signature".getBytes(StandardCharsets.UTF_8));

        return String.join(".", header, payload, signature);
    }
}
