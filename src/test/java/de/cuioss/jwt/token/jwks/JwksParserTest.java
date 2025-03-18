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
package de.cuioss.jwt.token.jwks;

import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = JwksParser.class)
@DisplayName("Tests JwksParser functionality")
class JwksParserTest {

    private static final String TEST_KID = JWKSFactory.TEST_KEY_ID;
    private final JwksParser jwksParser = new JwksParser();

    @Test
    @DisplayName("Should parse valid JWKS content")
    void shouldParseValidJwksContent() {
        // Given
        String jwksContent = JWKSFactory.createValidJwks();

        // When
        Map<String, Key> keys = jwksParser.parseJwks(jwksContent);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertEquals(1, keys.size(), "Should parse one key");
        assertTrue(keys.containsKey(TEST_KID), "Should contain key with ID: " + TEST_KID);
        assertNotNull(keys.get(TEST_KID), "Key should not be null");
    }

    @Test
    @DisplayName("Should handle invalid JSON format")
    void shouldHandleInvalidJsonFormat() {
        // Given
        String invalidJson = JWKSFactory.createInvalidJson();

        // When
        Map<String, Key> keys = jwksParser.parseJwks(invalidJson);

        // Then
        assertNotNull(keys, "Keys map should not be null even with invalid JSON");
        assertTrue(keys.isEmpty(), "Keys map should be empty with invalid JSON");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse JWKS JSON");
    }

    @Test
    @DisplayName("Should handle missing keys array")
    void shouldHandleMissingKeysArray() {
        // Given
        String noKeysJson = JWKSFactory.createJsonWithNoKeysArray();

        // When
        Map<String, Key> keys = jwksParser.parseJwks(noKeysJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertTrue(keys.isEmpty(), "Keys map should be empty when no keys array");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "JWKS JSON does not contain 'keys' array or 'kty' field");
    }

    @Test
    @DisplayName("Should handle empty keys array")
    void shouldHandleEmptyKeysArray() {
        // Given
        String emptyKeysJson = JWKSFactory.createEmptyJwks();

        // When
        Map<String, Key> keys = jwksParser.parseJwks(emptyKeysJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertTrue(keys.isEmpty(), "Keys map should be empty when keys array is empty");
    }

    @Test
    @DisplayName("Should handle missing required fields in JWK")
    void shouldHandleMissingRequiredFieldsInJwk() {
        // Given
        String missingFieldsJson = JWKSFactory.createJwksWithMissingFields(TEST_KID);

        // When
        Map<String, Key> keys = jwksParser.parseJwks(missingFieldsJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertTrue(keys.isEmpty(), "Keys map should be empty when JWK is missing required fields");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");
    }

    @Test
    @DisplayName("Should handle unsupported key type")
    void shouldHandleUnsupportedKeyType() {
        // Given
        String unsupportedTypeJson = JWKSFactory.createJwksWithUnsupportedKeyType(TEST_KID);

        // When
        Map<String, Key> keys = jwksParser.parseJwks(unsupportedTypeJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertTrue(keys.isEmpty(), "Keys map should be empty when key type is unsupported");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Unsupported key type: EC");
    }

    @Test
    @DisplayName("Should handle single JWK object (not in keys array)")
    void shouldHandleSingleJwkObject() {
        // Given
        String singleJwkJson = JWKSFactory.createSingleJwk(TEST_KID);

        // When
        Map<String, Key> keys = jwksParser.parseJwks(singleJwkJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertEquals(1, keys.size(), "Should parse one key");
        assertTrue(keys.containsKey(TEST_KID), "Should contain key with ID: " + TEST_KID);
        assertNotNull(keys.get(TEST_KID), "Key should not be null");
    }

    @Test
    @DisplayName("Should generate default key ID if not present")
    void shouldGenerateDefaultKeyIdIfNotPresent() {
        // Given
        String noKidJson = JWKSFactory.createJwksWithNoKeyId();

        // When
        Map<String, Key> keys = jwksParser.parseJwks(noKidJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertEquals(1, keys.size(), "Should parse one key");
        assertTrue(keys.containsKey("default-key-id"), "Should contain key with default ID");
        assertNotNull(keys.get("default-key-id"), "Key should not be null");
    }
}