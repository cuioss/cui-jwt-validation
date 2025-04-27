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
package de.cuioss.jwt.validation.security;

import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link AlgorithmPreferences}.
 * <p>
 * This test class verifies the functionality of the AlgorithmPreferences class,
 * which implements the requirement CUI-JWT-8.5: Cryptographic Agility as specified
 * in the security specification.
 * <p>
 * See: doc/specification/security.adoc
 */
@EnableTestLogger(debug = AlgorithmPreferences.class, warn = AlgorithmPreferences.class)
@DisplayName("Tests AlgorithmPreferences")
class AlgorithmPreferencesTest {

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Default constructor should initialize with default preferred algorithms")
        void defaultConstructorShouldInitializeWithDefaultPreferredAlgorithms() {
            // When
            AlgorithmPreferences preferences = new AlgorithmPreferences();

            // Then
            assertEquals(AlgorithmPreferences.getDefaultPreferredAlgorithms(), preferences.getPreferredAlgorithms(),
                    "Default constructor should initialize with default preferred algorithms");
        }

        @Test
        @DisplayName("Constructor with custom preferred algorithms should initialize correctly")
        void constructorWithCustomPreferredAlgorithmsShouldInitializeCorrectly() {
            // Given
            List<String> customAlgorithms = Arrays.asList("RS256", "ES256");

            // When
            AlgorithmPreferences preferences = new AlgorithmPreferences(customAlgorithms);

            // Then
            assertEquals(customAlgorithms, preferences.getPreferredAlgorithms(),
                    "Constructor should initialize with custom preferred algorithms");
        }

        @Test
        @DisplayName("Constructor should create an unmodifiable list")
        void constructorShouldCreateUnmodifiableList() {
            // Given
            List<String> customAlgorithms = Arrays.asList("RS256", "ES256");
            AlgorithmPreferences preferences = new AlgorithmPreferences(customAlgorithms);

            List<String> preferredAlgorithms = preferences.getPreferredAlgorithms();
            // When/Then
            assertThrows(UnsupportedOperationException.class, () -> preferredAlgorithms.add("RS384"),
                    "The preferred algorithms list should be unmodifiable");
        }
    }

    @Nested
    @DisplayName("getDefaultPreferredAlgorithms Tests")
    class GetDefaultPreferredAlgorithmsTests {

        @Test
        @DisplayName("getDefaultPreferredAlgorithms should return the expected default algorithms")
        void getDefaultPreferredAlgorithmsShouldReturnExpectedDefaultAlgorithms() {
            // When
            List<String> defaultAlgorithms = AlgorithmPreferences.getDefaultPreferredAlgorithms();

            // Then
            assertNotNull(defaultAlgorithms, "Default algorithms should not be null");
            assertFalse(defaultAlgorithms.isEmpty(), "Default algorithms should not be empty");

            // Verify the default algorithms include the expected ones
            List<String> expectedAlgorithms = Arrays.asList(
                    "ES512", "ES384", "ES256", "PS512", "PS384", "PS256", "RS512", "RS384", "RS256");
            assertEquals(expectedAlgorithms, defaultAlgorithms,
                    "Default algorithms should match the expected list");
        }

        // Note: We're not testing logging behavior as it's not critical to functionality
    }

    @Nested
    @DisplayName("isSupported Tests")
    class IsSupportedTests {

        @ParameterizedTest
        @DisplayName("isSupported should return true for supported algorithms")
        @ValueSource(strings = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"})
        void isSupportedShouldReturnTrueForSupportedAlgorithms(String algorithm) {
            // Given
            AlgorithmPreferences preferences = new AlgorithmPreferences();

            // When
            boolean isSupported = preferences.isSupported(algorithm);

            // Then
            assertTrue(isSupported, "Algorithm " + algorithm + " should be supported");
        }

        @ParameterizedTest
        @DisplayName("isSupported should return false for rejected algorithms")
        @ValueSource(strings = {"HS256", "HS384", "HS512", "none"})
        void isSupportedShouldReturnFalseForRejectedAlgorithms(String algorithm) {
            // Given
            AlgorithmPreferences preferences = new AlgorithmPreferences();

            // When
            boolean isSupported = preferences.isSupported(algorithm);

            // Then
            assertFalse(isSupported, "Algorithm " + algorithm + " should be rejected");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    "Algorithm " + algorithm + " is explicitly rejected for security reasons");
        }

        @ParameterizedTest
        @DisplayName("isSupported should return false for null or empty algorithm")
        @NullAndEmptySource
        void isSupportedShouldReturnFalseForNullOrEmptyAlgorithm(String algorithm) {
            // Given
            AlgorithmPreferences preferences = new AlgorithmPreferences();

            // When
            boolean isSupported = preferences.isSupported(algorithm);

            // Then
            assertFalse(isSupported, "Null or empty algorithm should not be supported");
        }

        @Test
        @DisplayName("isSupported should return false for unsupported algorithms")
        void isSupportedShouldReturnFalseForUnsupportedAlgorithms() {
            // Given
            AlgorithmPreferences preferences = new AlgorithmPreferences();

            // When
            boolean isSupported = preferences.isSupported("UNSUPPORTED_ALG");

            // Then
            assertFalse(isSupported, "Unsupported algorithm should return false");
        }

        @Test
        @DisplayName("isSupported should respect custom preferred algorithms")
        void isSupportedShouldRespectCustomPreferredAlgorithms() {
            // Given
            List<String> customAlgorithms = List.of("RS256");
            AlgorithmPreferences preferences = new AlgorithmPreferences(customAlgorithms);

            // When/Then
            assertTrue(preferences.isSupported("RS256"), "RS256 should be supported");
            assertFalse(preferences.isSupported("ES256"), "ES256 should not be supported");
        }
    }

    @Nested
    @DisplayName("getMostPreferredAlgorithm Tests")
    class GetMostPreferredAlgorithmTests {

        @Test
        @DisplayName("getMostPreferredAlgorithm should return the most preferred available algorithm")
        void getMostPreferredAlgorithmShouldReturnMostPreferredAvailableAlgorithm() {
            // Given
            AlgorithmPreferences preferences = new AlgorithmPreferences();
            List<String> availableAlgorithms = Arrays.asList("RS256", "ES256");

            // When
            Optional<String> result = preferences.getMostPreferredAlgorithm(availableAlgorithms);

            // Then
            assertTrue(result.isPresent(), "Result should be present");
            assertEquals("ES256", result.get(), "ES256 should be the most preferred available algorithm");
        }

        @Test
        @DisplayName("getMostPreferredAlgorithm should return empty for no matching algorithms")
        void getMostPreferredAlgorithmShouldReturnEmptyForNoMatchingAlgorithms() {
            // Given
            AlgorithmPreferences preferences = new AlgorithmPreferences();
            List<String> availableAlgorithms = List.of("UNSUPPORTED_ALG");

            // When
            Optional<String> result = preferences.getMostPreferredAlgorithm(availableAlgorithms);

            // Then
            assertFalse(result.isPresent(), "Result should be empty for no matching algorithms");
        }

        @Test
        @DisplayName("getMostPreferredAlgorithm should return empty for null available algorithms")
        void getMostPreferredAlgorithmShouldReturnEmptyForNullAvailableAlgorithms() {
            // Given
            AlgorithmPreferences preferences = new AlgorithmPreferences();

            // When
            Optional<String> result = preferences.getMostPreferredAlgorithm(null);

            // Then
            assertFalse(result.isPresent(), "Result should be empty for null available algorithms");
        }

        @Test
        @DisplayName("getMostPreferredAlgorithm should return empty for empty available algorithms")
        void getMostPreferredAlgorithmShouldReturnEmptyForEmptyAvailableAlgorithms() {
            // Given
            AlgorithmPreferences preferences = new AlgorithmPreferences();

            // When
            Optional<String> result = preferences.getMostPreferredAlgorithm(Collections.emptyList());

            // Then
            assertFalse(result.isPresent(), "Result should be empty for empty available algorithms");
        }

        @Test
        @DisplayName("getMostPreferredAlgorithm should respect order of preference")
        void getMostPreferredAlgorithmShouldRespectOrderOfPreference() {
            // Given
            AlgorithmPreferences preferences = new AlgorithmPreferences();
            // Available algorithms in reverse order of preference
            List<String> availableAlgorithms = Arrays.asList("RS256", "RS384", "RS512", "ES256", "ES384", "ES512");

            // When
            Optional<String> result = preferences.getMostPreferredAlgorithm(availableAlgorithms);

            // Then
            assertTrue(result.isPresent(), "Result should be present");
            assertEquals("ES512", result.get(), "ES512 should be the most preferred available algorithm");
        }

        @Test
        @DisplayName("getMostPreferredAlgorithm should work with custom preferences")
        void getMostPreferredAlgorithmShouldWorkWithCustomPreferences() {
            // Given
            List<String> customAlgorithms = Arrays.asList("RS256", "ES256");
            AlgorithmPreferences preferences = new AlgorithmPreferences(customAlgorithms);
            List<String> availableAlgorithms = Arrays.asList("ES256", "RS256");

            // When
            Optional<String> result = preferences.getMostPreferredAlgorithm(availableAlgorithms);

            // Then
            assertTrue(result.isPresent(), "Result should be present");
            assertEquals("RS256", result.get(), "RS256 should be the most preferred available algorithm");
        }
    }
}
