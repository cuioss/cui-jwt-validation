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

import de.cuioss.jwt.token.security.SecurityEventCounter;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link NonValidatingJwtParser}
 */
@DisplayName("Tests NonValidatingJwtParser functionality")
class NonValidatingJwtParserTest {

    // Sample token parts
    private static final String SAMPLE_HEADER = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key-id\"}";
    private static final String SAMPLE_PAYLOAD = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iss\":\"https://example.com\",\"exp\":1735689600}";
    private static final String SAMPLE_SIGNATURE = "signature";
    // Encoded token parts
    private static final String ENCODED_HEADER = Base64.getUrlEncoder().encodeToString(SAMPLE_HEADER.getBytes(StandardCharsets.UTF_8));
    private static final String ENCODED_PAYLOAD = Base64.getUrlEncoder().encodeToString(SAMPLE_PAYLOAD.getBytes(StandardCharsets.UTF_8));
    private static final String ENCODED_SIGNATURE = Base64.getUrlEncoder().encodeToString(SAMPLE_SIGNATURE.getBytes(StandardCharsets.UTF_8));
    // Complete token
    private static final String VALID_TOKEN = ENCODED_HEADER + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;
    private NonValidatingJwtParser parser;

    @BeforeEach
    void setUp() {
        parser = NonValidatingJwtParser.builder().securityEventCounter(new SecurityEventCounter()).build();
    }

    @Nested
    @DisplayName("Valid Token Tests")
    class ValidTokenTests {

        @Test
        @DisplayName("Should decode valid token")
        void shouldDecodeValidToken() {
            Optional<DecodedJwt> result = parser.decode(VALID_TOKEN);

            assertTrue(result.isPresent(), "Should decode a valid token");
            DecodedJwt jwt = result.get();

            // Verify header
            assertTrue(jwt.getHeader().isPresent(), "Header should be present");
            JsonObject header = jwt.getHeader().get();
            assertEquals("RS256", header.getString("alg"), "Algorithm should match");
            assertEquals("JWT", header.getString("typ"), "Type should match");
            assertEquals("test-key-id", header.getString("kid"), "Key ID should match");

            // Verify body
            assertTrue(jwt.getBody().isPresent(), "Body should be present");
            JsonObject body = jwt.getBody().get();
            assertEquals("1234567890", body.getString("sub"), "Subject should match");
            assertEquals("John Doe", body.getString("name"), "Name should match");
            assertEquals("https://example.com", body.getString("iss"), "Issuer should match");
            assertEquals(1735689600, body.getInt("exp"), "Expiration should match");

            // Verify signature
            assertTrue(jwt.getSignature().isPresent(), "Signature should be present");

            // Verify extracted fields
            assertTrue(jwt.getIssuer().isPresent(), "Issuer should be extracted");
            assertEquals("https://example.com", jwt.getIssuer().get(), "Extracted issuer should match");

            assertTrue(jwt.getKid().isPresent(), "Key ID should be extracted");
            assertEquals("test-key-id", jwt.getKid().get(), "Extracted key ID should match");

            // Verify raw token
            assertEquals(VALID_TOKEN, jwt.getRawToken(), "Raw token should match the original token");
        }
    }

    @Nested
    @DisplayName("Invalid Token Tests")
    class InvalidTokenTests {

        static Stream<Arguments> invalidTokenProvider() {
            return Stream.of(
                    Arguments.of("invalid.token", "Should not decode a token with invalid format"),
                    Arguments.of("invalid.base64.encoding", "Should not decode a token with invalid Base64 encoding")
            );
        }

        @ParameterizedTest
        @NullAndEmptySource
        @DisplayName("Should handle empty or null token")
        void shouldHandleEmptyOrNullToken(String token) {
            Optional<DecodedJwt> result = parser.decode(token);
            assertFalse(result.isPresent(), "Should not decode an empty or null token");
        }

        @ParameterizedTest
        @MethodSource("invalidTokenProvider")
        @DisplayName("Should handle invalid token format")
        void shouldHandleInvalidTokenFormat(String invalidToken, String message) {
            Optional<DecodedJwt> result = parser.decode(invalidToken);
            assertFalse(result.isPresent(), message);
        }

        @Test
        @DisplayName("Should handle invalid JSON")
        void shouldHandleInvalidJson() {
            String invalidHeader = Base64.getUrlEncoder().encodeToString("not json".getBytes(StandardCharsets.UTF_8));
            String invalidToken = invalidHeader + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            Optional<DecodedJwt> result = parser.decode(invalidToken);
            assertFalse(result.isPresent(), "Should not decode a token with invalid JSON");
        }
    }

    @Nested
    @DisplayName("Missing Field Tests")
    class MissingFieldTests {

        @Test
        @DisplayName("Should handle missing issuer")
        void shouldHandleMissingIssuer() {
            JsonObjectBuilder payloadBuilder = Json.createObjectBuilder()
                    .add("sub", "1234567890")
                    .add("name", "John Doe")
                    .add("exp", 1735689600);

            String payloadWithoutIssuer = payloadBuilder.build().toString();
            String encodedPayloadWithoutIssuer = Base64.getUrlEncoder().encodeToString(payloadWithoutIssuer.getBytes(StandardCharsets.UTF_8));
            String tokenWithoutIssuer = ENCODED_HEADER + "." + encodedPayloadWithoutIssuer + "." + ENCODED_SIGNATURE;

            Optional<DecodedJwt> result = parser.decode(tokenWithoutIssuer);

            assertTrue(result.isPresent(), "Should decode a token without issuer");
            DecodedJwt jwt = result.get();

            assertFalse(jwt.getIssuer().isPresent(), "Issuer should not be present");
            assertEquals(tokenWithoutIssuer, jwt.getRawToken(), "Raw token should match the original token");
        }

        @Test
        @DisplayName("Should handle missing kid")
        void shouldHandleMissingKid() {
            JsonObjectBuilder headerBuilder = Json.createObjectBuilder()
                    .add("alg", "RS256")
                    .add("typ", "JWT");

            String headerWithoutKid = headerBuilder.build().toString();
            String encodedHeaderWithoutKid = Base64.getUrlEncoder().encodeToString(headerWithoutKid.getBytes(StandardCharsets.UTF_8));
            String tokenWithoutKid = encodedHeaderWithoutKid + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            Optional<DecodedJwt> result = parser.decode(tokenWithoutKid);

            assertTrue(result.isPresent(), "Should decode a token without kid");
            DecodedJwt jwt = result.get();

            assertFalse(jwt.getKid().isPresent(), "Key ID should not be present");
            assertEquals(tokenWithoutKid, jwt.getRawToken(), "Raw token should match the original token");
        }
    }

    @Nested
    @DisplayName("Token Size Tests")
    class TokenSizeTests {

        @Test
        @DisplayName("Should respect max token size")
        void shouldRespectMaxTokenSize() {
            // Create a token that exceeds the max size

            Optional<DecodedJwt> result = parser.decode("a".repeat(TokenFactoryConfig.DEFAULT_MAX_TOKEN_SIZE + 1));
            assertFalse(result.isPresent(), "Should not decode a token that exceeds max size");
        }

        @Test
        @DisplayName("Should respect custom max token size")
        void shouldRespectCustomMaxTokenSize() {
            // Create a token that exceeds the custom max size but is smaller than the default
            int customMaxSize = 1024;
            String largeToken = "a".repeat(customMaxSize + 1);

            TokenFactoryConfig config = TokenFactoryConfig.builder()
                    .maxTokenSize(customMaxSize)
                    .build();

            NonValidatingJwtParser customParser = NonValidatingJwtParser.builder().securityEventCounter(new SecurityEventCounter())
                    .config(config)
                    .build();

            Optional<DecodedJwt> result = customParser.decode(largeToken);
            assertFalse(result.isPresent(), "Should not decode a token that exceeds custom max size");
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should create builder with defaults")
        void shouldCreateBuilderWithDefaults() {
            NonValidatingJwtParser defaultParser = NonValidatingJwtParser.builder().securityEventCounter(new SecurityEventCounter()).build();
            assertNotNull(defaultParser, "Should create a parser with default settings");

            // Verify it works with a valid token
            Optional<DecodedJwt> result = defaultParser.decode(VALID_TOKEN);
            assertTrue(result.isPresent(), "Default parser should decode a valid token");
            assertEquals(VALID_TOKEN, result.get().getRawToken(), "Raw token should match the original token");
        }
    }

    @Nested
    @DisplayName("Security Measures Tests")
    class SecurityMeasuresTest {

        @Test
        @DisplayName("Should respect JSON depth limits")
        void shouldRespectJsonDepthLimits() {
            // Create a deeply nested JSON structure that exceeds the max depth
            StringBuilder nestedJson = new StringBuilder("{");
            for (int i = 0; i < TokenFactoryConfig.DEFAULT_MAX_DEPTH + 1; i++) {
                nestedJson.append("\"level").append(i).append("\":{");
            }
            // Close all the nested objects
            nestedJson.append("}".repeat(TokenFactoryConfig.DEFAULT_MAX_DEPTH + 1));

            String encodedNestedJson = Base64.getUrlEncoder().encodeToString(nestedJson.toString().getBytes(StandardCharsets.UTF_8));
            String tokenWithDeepJson = encodedNestedJson + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            Optional<DecodedJwt> result = parser.decode(tokenWithDeepJson);
            assertFalse(result.isPresent(), "Should not decode a token with JSON exceeding max depth");
        }

        @Test
        @DisplayName("Should handle large JSON arrays")
        void shouldHandleLargeJsonArrays() {
            // Create a JSON with a large array
            StringBuilder largeArrayJson = new StringBuilder("{\"array\":[");
            for (int i = 0; i < TokenFactoryConfig.DEFAULT_MAX_ARRAY_SIZE - 1; i++) {
                if (i > 0) {
                    largeArrayJson.append(",");
                }
                largeArrayJson.append("\"item").append(i).append("\"");
            }
            largeArrayJson.append("]}");

            String encodedLargeArrayJson = Base64.getUrlEncoder().encodeToString(largeArrayJson.toString().getBytes(StandardCharsets.UTF_8));
            String tokenWithLargeArray = encodedLargeArrayJson + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            Optional<DecodedJwt> result = parser.decode(tokenWithLargeArray);
            assertTrue(result.isPresent(), "Should decode a token with large JSON array within limits");

            // Verify the array was parsed correctly
            assertTrue(result.get().getHeader().isPresent(), "Header should be present");
            JsonObject header = result.get().getHeader().get();
            assertTrue(header.containsKey("array"), "Array should be present in header");
        }

        @Test
        @DisplayName("Should handle large JSON strings")
        void shouldHandleLargeJsonStrings() {
            // Create a JSON with a large string
            String largeStringJson = "{\"largeString\":\"" + "a".repeat(TokenFactoryConfig.DEFAULT_MAX_STRING_SIZE - 100) + "\"}";

            String encodedLargeStringJson = Base64.getUrlEncoder().encodeToString(largeStringJson.getBytes(StandardCharsets.UTF_8));
            String tokenWithLargeString = encodedLargeStringJson + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            Optional<DecodedJwt> result = parser.decode(tokenWithLargeString);
            assertTrue(result.isPresent(), "Should decode a token with large JSON string within limits");

            // Verify the string was parsed correctly
            assertTrue(result.get().getHeader().isPresent(), "Header should be present");
            JsonObject header = result.get().getHeader().get();
            assertTrue(header.containsKey("largeString"), "Large string should be present in header");
        }

        @Test
        @DisplayName("Should use cached JsonReaderFactory")
        void shouldUseCachedJsonReaderFactory() {
            // This test verifies that the JsonReaderFactory is cached and reused
            // We can't directly test the caching behavior, but we can verify that
            // the parser works correctly after the JsonReaderFactory is created

            // First decode should create and cache the JsonReaderFactory
            Optional<DecodedJwt> result1 = parser.decode(VALID_TOKEN);
            assertTrue(result1.isPresent(), "First decode should succeed");

            // Second decode should use the cached JsonReaderFactory
            Optional<DecodedJwt> result2 = parser.decode(VALID_TOKEN);
            assertTrue(result2.isPresent(), "Second decode should succeed");

            // Both results should be equal
            assertEquals(result1.get().getRawToken(), result2.get().getRawToken(),
                    "Both decodes should produce the same result");
        }
    }
}
