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
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = AbstractJwksLoader.class)
@DisplayName("Tests AbstractJwksLoader functionality")
class AbstractJwksLoaderTest {

    private static final String TEST_KID = JWKSFactory.TEST_KEY_ID;

    /**
     * Concrete implementation of AbstractJwksLoader for testing.
     */
    private static class TestJwksLoader extends AbstractJwksLoader {
        private Map<String, Key> keys;

        @Override
        public Optional<Key> getKey(String kid) {
            return Optional.ofNullable(keys != null ? keys.get(kid) : null);
        }

        @Override
        public Optional<Key> getFirstKey() {
            if (keys == null || keys.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(keys.values().iterator().next());
        }

        @Override
        public void refreshKeys() {
            // No-op for testing
        }

        /**
         * Expose the protected parseJwks method for testing.
         */
        public Map<String, Key> testParseJwks(String jwksContent) {
            keys = parseJwks(jwksContent);
            return keys;
        }
    }

    @Test
    @DisplayName("Should parse valid JWKS content")
    void shouldParseValidJwksContent() {
        // Given
        TestJwksLoader loader = new TestJwksLoader();
        String jwksContent = JWKSFactory.createValidJwks();

        // When
        Map<String, Key> keys = loader.testParseJwks(jwksContent);

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
        TestJwksLoader loader = new TestJwksLoader();
        String invalidJson = JWKSFactory.createInvalidJson();

        // When
        Map<String, Key> keys = loader.testParseJwks(invalidJson);

        // Then
        assertNotNull(keys, "Keys map should not be null even with invalid JSON");
        assertTrue(keys.isEmpty(), "Keys map should be empty with invalid JSON");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse JWKS JSON");
    }

    @Test
    @DisplayName("Should handle missing keys array")
    void shouldHandleMissingKeysArray() {
        // Given
        TestJwksLoader loader = new TestJwksLoader();
        String noKeysJson = JWKSFactory.createJsonWithNoKeysArray();

        // When
        Map<String, Key> keys = loader.testParseJwks(noKeysJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertTrue(keys.isEmpty(), "Keys map should be empty when no keys array");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "JWKS JSON does not contain 'keys' array or 'kty' field");
    }

    @Test
    @DisplayName("Should handle empty keys array")
    void shouldHandleEmptyKeysArray() {
        // Given
        TestJwksLoader loader = new TestJwksLoader();
        String emptyKeysJson = JWKSFactory.createEmptyJwks();

        // When
        Map<String, Key> keys = loader.testParseJwks(emptyKeysJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertTrue(keys.isEmpty(), "Keys map should be empty when keys array is empty");
    }

    @Test
    @DisplayName("Should handle missing required fields in JWK")
    void shouldHandleMissingRequiredFieldsInJwk() {
        // Given
        TestJwksLoader loader = new TestJwksLoader();
        String missingFieldsJson = JWKSFactory.createJwksWithMissingFields(TEST_KID);

        // When
        Map<String, Key> keys = loader.testParseJwks(missingFieldsJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertTrue(keys.isEmpty(), "Keys map should be empty when JWK is missing required fields");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");
    }

    @Test
    @DisplayName("Should handle unsupported key type")
    void shouldHandleUnsupportedKeyType() {
        // Given
        TestJwksLoader loader = new TestJwksLoader();
        String unsupportedTypeJson = JWKSFactory.createJwksWithUnsupportedKeyType(TEST_KID);

        // When
        Map<String, Key> keys = loader.testParseJwks(unsupportedTypeJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertTrue(keys.isEmpty(), "Keys map should be empty when key type is unsupported");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Unsupported key type: EC");
    }

    @Test
    @DisplayName("Should handle single JWK object (not in keys array)")
    void shouldHandleSingleJwkObject() {
        // Given
        TestJwksLoader loader = new TestJwksLoader();
        String singleJwkJson = JWKSFactory.createSingleJwk(TEST_KID);

        // When
        Map<String, Key> keys = loader.testParseJwks(singleJwkJson);

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
        TestJwksLoader loader = new TestJwksLoader();
        String noKidJson = JWKSFactory.createJwksWithNoKeyId();

        // When
        Map<String, Key> keys = loader.testParseJwks(noKidJson);

        // Then
        assertNotNull(keys, "Keys map should not be null");
        assertEquals(1, keys.size(), "Should parse one key");
        assertTrue(keys.containsKey("default-key-id"), "Should contain key with default ID");
        assertNotNull(keys.get("default-key-id"), "Key should not be null");
    }
}
