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

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for {@link NonValidatingJwtParser}
 */
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
        parser = NonValidatingJwtParser.builder().build();
    }

    @Test
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

    @Test
    void shouldHandleEmptyToken() {
        Optional<DecodedJwt> result = parser.decode("");
        assertFalse(result.isPresent(), "Should not decode an empty token");
    }

    @Test
    void shouldHandleNullToken() {
        Optional<DecodedJwt> result = parser.decode(null);
        assertFalse(result.isPresent(), "Should not decode a null token");
    }

    @Test
    void shouldHandleInvalidTokenFormat() {
        Optional<DecodedJwt> result = parser.decode("invalid.token");
        assertFalse(result.isPresent(), "Should not decode a token with invalid format");
    }

    @Test
    void shouldHandleInvalidBase64() {
        Optional<DecodedJwt> result = parser.decode("invalid.base64.encoding");
        assertFalse(result.isPresent(), "Should not decode a token with invalid Base64 encoding");
    }

    @Test
    void shouldHandleInvalidJson() {
        String invalidHeader = Base64.getUrlEncoder().encodeToString("not json".getBytes(StandardCharsets.UTF_8));
        String invalidToken = invalidHeader + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

        Optional<DecodedJwt> result = parser.decode(invalidToken);
        assertFalse(result.isPresent(), "Should not decode a token with invalid JSON");
    }

    @Test
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

    @Test
    void shouldRespectMaxTokenSize() {
        // Create a token that exceeds the max size
        StringBuilder largeToken = new StringBuilder();
        for (int i = 0; i < NonValidatingJwtParser.DEFAULT_MAX_TOKEN_SIZE + 1; i++) {
            largeToken.append("a");
        }

        Optional<DecodedJwt> result = parser.decode(largeToken.toString());
        assertFalse(result.isPresent(), "Should not decode a token that exceeds max size");
    }

    @Test
    void shouldRespectCustomMaxTokenSize() {
        // Create a token that exceeds the custom max size but is smaller than the default
        int customMaxSize = 1024;
        StringBuilder largeToken = new StringBuilder();
        for (int i = 0; i < customMaxSize + 1; i++) {
            largeToken.append("a");
        }

        NonValidatingJwtParser customParser = NonValidatingJwtParser.builder()
                .maxTokenSize(customMaxSize)
                .build();

        Optional<DecodedJwt> result = customParser.decode(largeToken.toString());
        assertFalse(result.isPresent(), "Should not decode a token that exceeds custom max size");
    }

    @Test
    void shouldCreateBuilderWithDefaults() {
        NonValidatingJwtParser defaultParser = NonValidatingJwtParser.builder().build();
        assertNotNull(defaultParser, "Should create a parser with default settings");

        // Verify it works with a valid token
        Optional<DecodedJwt> result = defaultParser.decode(VALID_TOKEN);
        assertTrue(result.isPresent(), "Default parser should decode a valid token");
        assertEquals(VALID_TOKEN, result.get().getRawToken(), "Raw token should match the original token");
    }
}
