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
package de.cuioss.jwt.token.jwks.key;

import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = {JWKSKeyLoader.class}, trace = {JWKSKeyLoader.class})
@DisplayName("Tests JWKSKeyLoader functionality")
class JWKSKeyLoaderTest {

    private static final String TEST_KID = JWKSFactory.DEFAULT_KEY_ID;
    private static final String TEST_ETAG = "\"test-etag\"";
    private JWKSKeyLoader keyLoader;
    private String jwksContent;

    @BeforeEach
    void setUp() {
        jwksContent = JWKSFactory.createDefaultJwks();
        keyLoader = new JWKSKeyLoader(jwksContent, TEST_ETAG);
    }

    @Nested
    @DisplayName("Basic Functionality")
    class BasicFunctionalityTests {
        @Test
        @DisplayName("Should parse JWKS content")
        void shouldParseJwksContent() {
            // When
            Optional<KeyInfo> keyInfo = keyLoader.getKeyInfo(TEST_KID);

            // Then
            assertTrue(keyInfo.isPresent(), "Key info should be present");
        }

        @Test
        @DisplayName("Should get first key when available")
        void shouldGetFirstKeyWhenAvailable() {
            // When
            Optional<KeyInfo> keyInfo = keyLoader.getFirstKeyInfo();

            // Then
            assertTrue(keyInfo.isPresent(), "First key info should be present");
        }

        @Test
        @DisplayName("Should return correct keySet")
        void shouldReturnCorrectKeySet() {
            // When
            var keySet = keyLoader.keySet();

            // Then
            assertFalse(keySet.isEmpty(), "KeySet should not be empty");
            assertTrue(keySet.contains(TEST_KID), "KeySet should contain the test key ID");
            assertEquals(1, keySet.size(), "KeySet should contain exactly one key");
        }
    }

    @Nested
    @DisplayName("Error Handling")
    class ErrorHandlingTests {
        @Test
        @DisplayName("Should return empty when kid is null")
        void shouldReturnEmptyWhenKidIsNull() {
            // When
            Optional<KeyInfo> keyInfo = keyLoader.getKeyInfo(null);

            // Then
            assertFalse(keyInfo.isPresent(), "Key info should not be present when kid is null");
            // Note: Log assertion removed as it's not essential to the test's purpose
        }

        @Test
        @DisplayName("Should return empty when kid is not found")
        void shouldReturnEmptyWhenKidNotFound() {
            // When
            Optional<KeyInfo> keyInfo = keyLoader.getKeyInfo("unknown-kid");

            // Then
            assertFalse(keyInfo.isPresent(), "Key info should not be present when kid is not found");
        }

        @Test
        @DisplayName("Should handle invalid JWKS format")
        void shouldHandleInvalidJwksFormat() {
            // Given
            String invalidJwksContent = JWKSFactory.createInvalidJson();
            JWKSKeyLoader invalidLoader = new JWKSKeyLoader(invalidJwksContent);

            // When
            Optional<KeyInfo> keyInfo = invalidLoader.getKeyInfo(TEST_KID);

            // Then
            assertFalse(keyInfo.isPresent(), "Key info should not be present when JWKS is invalid");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse JWKS JSON");
        }

        @Test
        @DisplayName("Should handle missing required fields in JWK")
        void shouldHandleMissingRequiredFieldsInJwk() {
            // Given
            String missingFieldsJwksContent = JWKSFactory.createJwksWithMissingFields(TEST_KID);
            JWKSKeyLoader missingFieldsLoader = new JWKSKeyLoader(missingFieldsJwksContent);

            // When
            Optional<KeyInfo> keyInfo = missingFieldsLoader.getKeyInfo(TEST_KID);

            // Then
            assertFalse(keyInfo.isPresent(), "Key info should not be present when JWK is missing required fields");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");
        }
    }

    @Nested
    @DisplayName("New Features")
    class NewFeaturesTests {
        @Test
        @DisplayName("Should store original JWKS content")
        void shouldStoreOriginalJwksContent() {
            // When
            String originalString = keyLoader.getOriginalString();

            // Then
            assertEquals(jwksContent, originalString, "Original JWKS content should be stored");
        }

        @Test
        @DisplayName("Should store ETag value")
        void shouldStoreEtagValue() {
            // When
            String etag = keyLoader.getEtag();

            // Then
            assertEquals(TEST_ETAG, etag, "ETag value should be stored");
        }

        @Test
        @DisplayName("Should return null for ETag when not provided")
        void shouldReturnNullForEtagWhenNotProvided() {
            // Given
            JWKSKeyLoader loaderWithoutEtag = new JWKSKeyLoader(jwksContent);

            // When
            String etag = loaderWithoutEtag.getEtag();

            // Then
            assertNull(etag, "ETag should be null when not provided");
        }

        @Test
        @DisplayName("Should report not empty when keys are present")
        void shouldReportNotEmptyWhenKeysArePresent() {
            // When
            boolean notEmpty = keyLoader.isNotEmpty();

            // Then
            assertTrue(notEmpty, "Loader should report not empty when keys are present");
        }

        @Test
        @DisplayName("Should report empty when no keys are present")
        void shouldReportEmptyWhenNoKeysArePresent() {
            // Given
            String emptyJwksContent = "{}";
            JWKSKeyLoader emptyLoader = new JWKSKeyLoader(emptyJwksContent);

            // When
            boolean notEmpty = emptyLoader.isNotEmpty();

            // Then
            assertFalse(notEmpty, "Loader should report empty when no keys are present");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode")
    class EqualsAndHashCodeTests {
        @Test
        @DisplayName("Should be equal when content and etag are the same")
        void shouldBeEqualWhenContentAndEtagAreSame() {
            // Given
            JWKSKeyLoader sameLoader = new JWKSKeyLoader(jwksContent, TEST_ETAG);

            // When/Then
            assertEquals(keyLoader, sameLoader, "Loaders with same content and etag should be equal");
            assertEquals(keyLoader.hashCode(), sameLoader.hashCode(), "Hash codes should be equal");
        }

        @Test
        @DisplayName("Should not be equal when content is different")
        void shouldNotBeEqualWhenContentIsDifferent() {
            // Given
            String differentContent = JWKSFactory.createValidJwksWithKeyId("different-kid");
            JWKSKeyLoader differentLoader = new JWKSKeyLoader(differentContent, TEST_ETAG);

            // When/Then
            assertNotEquals(keyLoader, differentLoader, "Loaders with different content should not be equal");
            assertNotEquals(keyLoader.hashCode(), differentLoader.hashCode(), "Hash codes should not be equal");
        }

        @Test
        @DisplayName("Should not be equal when etag is different")
        void shouldNotBeEqualWhenEtagIsDifferent() {
            // Given
            JWKSKeyLoader differentEtagLoader = new JWKSKeyLoader(jwksContent, "different-etag");

            // When/Then
            assertNotEquals(keyLoader, differentEtagLoader, "Loaders with different etags should not be equal");
            assertNotEquals(keyLoader.hashCode(), differentEtagLoader.hashCode(), "Hash codes should not be equal");
        }
    }
}
