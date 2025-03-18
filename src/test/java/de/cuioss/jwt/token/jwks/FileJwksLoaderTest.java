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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger(debug = {JWKSKeyLoader.class, JwksClientFactory.class})
@DisplayName("Tests file-based JWKSKeyLoader functionality")
class FileJwksLoaderTest {

    private static final String TEST_KID = JWKSFactory.TEST_KEY_ID;

    @TempDir
    Path tempDir;

    private Path jwksFilePath;
    private JwksLoader fileJwksLoader;

    @BeforeEach
    void setUp() throws IOException {
        // Create a temporary JWKS file for testing
        jwksFilePath = tempDir.resolve("jwks.json");
        String jwksContent = JWKSFactory.createValidJwks();
        Files.writeString(jwksFilePath, jwksContent);

        // Create the FileJwksLoader with the temporary file
        fileJwksLoader = JwksClientFactory.createFileLoader(jwksFilePath.toString());
    }

    @AfterEach
    void tearDown() {
        // No cleanup needed
    }

    @Test
    @DisplayName("Should load and parse JWKS from file")
    void shouldLoadAndParseJwks() {
        // When
        Optional<Key> key = fileJwksLoader.getKey(TEST_KID);

        // Then
        assertTrue(key.isPresent(), "Key should be present");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Resolving key loader for JWKS file");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Successfully loaded");
    }

    @Test
    @DisplayName("Should return empty when kid is null")
    void shouldReturnEmptyWhenKidIsNull() {
        // When
        Optional<Key> key = fileJwksLoader.getKey(null);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when kid is null");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Key ID is null");
    }

    @Test
    @DisplayName("Should return empty when kid is not found")
    void shouldReturnEmptyWhenKidNotFound() {
        // When
        Optional<Key> key = fileJwksLoader.getKey("unknown-kid");

        // Then
        assertFalse(key.isPresent(), "Key should not be present when kid is not found");
    }

    @Test
    @DisplayName("Should get first key when available")
    void shouldGetFirstKeyWhenAvailable() {
        // When
        Optional<Key> key = fileJwksLoader.getFirstKey();

        // Then
        assertTrue(key.isPresent(), "First key should be present");
    }

    @Test
    @DisplayName("Should handle file not found")
    void shouldHandleFileNotFound() {
        // Given
        JwksLoader nonExistentFileLoader = JwksClientFactory.createFileLoader(tempDir.resolve("non-existent.json").toString());

        // When
        Optional<Key> key = nonExistentFileLoader.getKey(TEST_KID);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when file is not found");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to read JWKS from file");

        // No cleanup needed
    }

    @Test
    @DisplayName("Should handle invalid JWKS format")
    void shouldHandleInvalidJwksFormat() throws IOException {
        // Given
        Path invalidJwksPath = tempDir.resolve("invalid-jwks.json");
        Files.writeString(invalidJwksPath, JWKSFactory.createInvalidJson());
        JwksLoader invalidJwksLoader = JwksClientFactory.createFileLoader(invalidJwksPath.toString());

        // When
        Optional<Key> key = invalidJwksLoader.getKey(TEST_KID);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when JWKS is invalid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse JWKS JSON");

        // No cleanup needed
    }

    @Test
    @DisplayName("Should handle missing required fields in JWK")
    void shouldHandleMissingRequiredFieldsInJwk() throws IOException {
        // Given
        Path missingFieldsJwksPath = tempDir.resolve("missing-fields-jwks.json");
        String missingFieldsJwksContent = JWKSFactory.createJwksWithMissingFields(TEST_KID);
        Files.writeString(missingFieldsJwksPath, missingFieldsJwksContent);
        JwksLoader missingFieldsJwksLoader = JwksClientFactory.createFileLoader(missingFieldsJwksPath.toString());

        // When
        Optional<Key> key = missingFieldsJwksLoader.getKey(TEST_KID);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when JWK is missing required fields");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");

        // No cleanup needed
    }

    @Test
    @DisplayName("Should refresh keys when file is updated")
    void shouldRefreshKeysWhenFileIsUpdated() throws IOException {
        // Given
        Optional<Key> initialKey = fileJwksLoader.getKey(TEST_KID);
        assertTrue(initialKey.isPresent(), "Initial key should be present");

        // When - update the file with new content
        String updatedJwksContent = JWKSFactory.createValidJwksWithKeyId("updated-key-id");
        Files.writeString(jwksFilePath, updatedJwksContent);

        // Create a new FileJwksLoader to force refresh
        JwksLoader newLoader = JwksClientFactory.createFileLoader(jwksFilePath.toString());

        // Then - verify the old key is no longer available and the new key is
        Optional<Key> oldKey = newLoader.getKey(TEST_KID);
        assertFalse(oldKey.isPresent(), "Old key should no longer be present");

        Optional<Key> newKey = newLoader.getKey("updated-key-id");
        assertTrue(newKey.isPresent(), "New key should be present");
    }

    @Test
    @DisplayName("Should return correct keySet")
    void shouldReturnCorrectKeySet() {
        // Given
        // The loader is already initialized with a valid JWKS file in setUp()

        // When
        var keySet = fileJwksLoader.keySet();

        // Then
        assertFalse(keySet.isEmpty(), "KeySet should not be empty");
        assertTrue(keySet.contains(TEST_KID), "KeySet should contain the test key ID");
        assertEquals(1, keySet.size(), "KeySet should contain exactly one key");
    }
}
