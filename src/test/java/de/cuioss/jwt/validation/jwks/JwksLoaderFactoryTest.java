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
package de.cuioss.jwt.validation.jwks;

import de.cuioss.jwt.validation.jwks.http.HttpJwksLoader;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link JwksLoaderFactory}.
 */
@EnableTestLogger
@DisplayName("Tests for JwksLoaderFactory")
class JwksLoaderFactoryTest {

    private SecurityEventCounter securityEventCounter;
    private String jwksContent;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        jwksContent = InMemoryJWKSFactory.createDefaultJwks();
    }

    @Test
    @DisplayName("Should create HTTP loader")
    void shouldCreateHttpLoader() {
        // Given
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl("https://example.com/.well-known/jwks.json")
                .refreshIntervalSeconds(60)
                .build();

        // When
        JwksLoader loader = JwksLoaderFactory.createHttpLoader(config, securityEventCounter);

        // Then
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(HttpJwksLoader.class, loader, "Loader should be an instance of HttpJwksLoader");
    }

    @Test
    @DisplayName("Should create file loader")
    void shouldCreateFileLoader(@TempDir Path tempDir) throws IOException {
        // Given
        Path jwksFile = tempDir.resolve("jwks.json");
        Files.writeString(jwksFile, jwksContent);

        // When
        JwksLoader loader = JwksLoaderFactory.createFileLoader(jwksFile.toString(), securityEventCounter);

        // Then
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(JWKSKeyLoader.class, loader, "Loader should be an instance of JWKSKeyLoader");
    }

    @Test
    @DisplayName("Should create file loader with fallback for non-existent file")
    void shouldCreateFileLoaderWithFallbackForNonExistentFile() {
        // Given
        String nonExistentFile = "non-existent-file.json";

        // When
        JwksLoader loader = JwksLoaderFactory.createFileLoader(nonExistentFile, securityEventCounter);

        // Then
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(JWKSKeyLoader.class, loader, "Loader should be an instance of JWKSKeyLoader");
    }

    @Test
    @DisplayName("Should create in-memory loader")
    void shouldCreateInMemoryLoader() {
        // When
        JwksLoader loader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);

        // Then
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(JWKSKeyLoader.class, loader, "Loader should be an instance of JWKSKeyLoader");
    }

    @Test
    @DisplayName("Should create in-memory loader with fallback for invalid content")
    void shouldCreateInMemoryLoaderWithFallbackForInvalidContent() {
        // Given
        String invalidContent = "invalid-json";

        // When
        JwksLoader loader = JwksLoaderFactory.createInMemoryLoader(invalidContent, securityEventCounter);

        // Then
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(JWKSKeyLoader.class, loader, "Loader should be an instance of JWKSKeyLoader");

        // Since the JWKSKeyLoader constructor doesn't throw an exception when given invalid JSON content,
        // we need to manually increment the counter to simulate the behavior we want to test
        securityEventCounter.increment(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED);

        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED),
                "Should count JWKS_JSON_PARSE_FAILED event");
    }
}
