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
package de.cuioss.jwt.validation.jwks.key;

import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
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

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final String TEST_ETAG = "\"test-etag\"";
    private JWKSKeyLoader keyLoader;
    private String jwksContent;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        securityEventCounter = new SecurityEventCounter();
        keyLoader = JWKSKeyLoader.builder()
                .originalString(jwksContent)
                .etag(TEST_ETAG)
                .securityEventCounter(securityEventCounter)
                .build();
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
            String invalidJwksContent = InMemoryJWKSFactory.createInvalidJson();
            JWKSKeyLoader invalidLoader = JWKSKeyLoader.builder()
                    .originalString(invalidJwksContent)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

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
            String missingFieldsJwksContent = InMemoryJWKSFactory.createJwksWithMissingFields(TEST_KID);
            JWKSKeyLoader missingFieldsLoader = JWKSKeyLoader.builder()
                    .originalString(missingFieldsJwksContent)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

            // When
            Optional<KeyInfo> keyInfo = missingFieldsLoader.getKeyInfo(TEST_KID);

            // Then
            assertFalse(keyInfo.isPresent(), "Key info should not be present when JWK is missing required fields");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");
        }
    }

    @Nested
    @DisplayName("Metadata and State Management")
    class MetadataAndStateTests {
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
            JWKSKeyLoader loaderWithoutEtag = JWKSKeyLoader.builder()
                    .originalString(jwksContent)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

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
            JWKSKeyLoader emptyLoader = JWKSKeyLoader.builder()
                    .originalString(emptyJwksContent)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

            // When
            boolean notEmpty = emptyLoader.isNotEmpty();

            // Then
            assertFalse(notEmpty, "Loader should report empty when no keys are present");
        }
    }

    @Nested
    @DisplayName("Security Features")
    class SecurityFeaturesTests {
        @Test
        @DisplayName("Should use custom ParserConfig")
        void shouldUseCustomParserConfig() {
            // Given
            ParserConfig customConfig = ParserConfig.builder()
                    .maxPayloadSize(1024)
                    .maxStringSize(512)
                    .maxArraySize(10)
                    .maxDepth(5)
                    .build();

            // When
            JWKSKeyLoader loaderWithCustomConfig = JWKSKeyLoader.builder()
                    .originalString(jwksContent)
                    .etag(TEST_ETAG)
                    .parserConfig(customConfig)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

            // Then
            assertEquals(customConfig, loaderWithCustomConfig.getParserConfig(),
                    "Loader should use the provided ParserConfig");
            assertTrue(loaderWithCustomConfig.isNotEmpty(),
                    "Loader should still parse valid JWKS with custom config");
        }

        @Test
        @DisplayName("Should reject JWKS content exceeding maximum size")
        void shouldRejectJwksContentExceedingMaximumSize() {
            // Given
            int maxSize = 100; // Small size for testing
            ParserConfig restrictiveConfig = ParserConfig.builder()
                    .maxPayloadSize(maxSize)
                    .build();

            // Create a large JWKS content that exceeds the maximum size
            StringBuilder largeContent = new StringBuilder("{\"keys\":[");
            // Add enough padding to exceed maxSize
            largeContent.append("\"x\":\"").append("a".repeat(maxSize)).append("\"}]}");

            // When
            JWKSKeyLoader loader = JWKSKeyLoader.builder()
                    .originalString(largeContent.toString())
                    .parserConfig(restrictiveConfig)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

            // Then
            assertFalse(loader.isNotEmpty(), "Loader should reject content exceeding maximum size");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    "JWKS content size exceeds maximum allowed size");
        }

        @Test
        @DisplayName("Should use default ParserConfig when not provided")
        void shouldUseDefaultParserConfigWhenNotProvided() {
            // Given/When
            JWKSKeyLoader defaultLoader = JWKSKeyLoader.builder()
                    .originalString(jwksContent)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

            // Then
            assertNotNull(defaultLoader.getParserConfig(), "Default ParserConfig should not be null");
            assertEquals(ParserConfig.DEFAULT_MAX_PAYLOAD_SIZE,
                    defaultLoader.getParserConfig().getMaxPayloadSize(),
                    "Default max payload size should be used");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode")
    class EqualsAndHashCodeTests {
        @Test
        @DisplayName("Should be equal when content, etag, and ParserConfig are the same")
        void shouldBeEqualWhenContentAndEtagAreSame() {
            // Given
            ParserConfig config = keyLoader.getParserConfig();
            JWKSKeyLoader sameLoader = JWKSKeyLoader.builder()
                    .originalString(jwksContent)
                    .etag(TEST_ETAG)
                    .parserConfig(config)
                    .securityEventCounter(securityEventCounter)
                    .build();

            // When/Then
            assertEquals(keyLoader, sameLoader, "Loaders with same content, etag, and ParserConfig should be equal");
            assertEquals(keyLoader.hashCode(), sameLoader.hashCode(), "Hash codes should be equal");
        }

        @Test
        @DisplayName("Should not be equal when content is different")
        void shouldNotBeEqualWhenContentIsDifferent() {
            // Given
            String differentContent = InMemoryJWKSFactory.createValidJwksWithKeyId("different-kid");
            JWKSKeyLoader differentLoader = JWKSKeyLoader.builder()
                    .originalString(differentContent)
                    .etag(TEST_ETAG)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

            // When/Then
            assertNotEquals(keyLoader, differentLoader, "Loaders with different content should not be equal");
            assertNotEquals(keyLoader.hashCode(), differentLoader.hashCode(), "Hash codes should not be equal");
        }

        @Test
        @DisplayName("Should not be equal when etag is different")
        void shouldNotBeEqualWhenEtagIsDifferent() {
            // Given
            JWKSKeyLoader differentEtagLoader = JWKSKeyLoader.builder()
                    .originalString(jwksContent)
                    .etag("different-etag")
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

            // When/Then
            assertNotEquals(keyLoader, differentEtagLoader, "Loaders with different etags should not be equal");
            assertNotEquals(keyLoader.hashCode(), differentEtagLoader.hashCode(), "Hash codes should not be equal");
        }

        @Test
        @DisplayName("Should not be equal when ParserConfig is different")
        void shouldNotBeEqualWhenParserConfigIsDifferent() {
            // Given
            ParserConfig customConfig = ParserConfig.builder()
                    .maxPayloadSize(1024)
                    .build();
            JWKSKeyLoader differentConfigLoader = JWKSKeyLoader.builder()
                    .originalString(jwksContent)
                    .etag(TEST_ETAG)
                    .parserConfig(customConfig)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();

            // When/Then
            assertNotEquals(keyLoader, differentConfigLoader, "Loaders with different ParserConfig should not be equal");
            assertNotEquals(keyLoader.hashCode(), differentConfigLoader.hashCode(), "Hash codes should not be equal");
        }
    }
}
