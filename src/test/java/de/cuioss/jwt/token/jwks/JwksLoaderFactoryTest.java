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
import de.cuioss.jwt.token.test.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.MockWebServerHolder;
import de.cuioss.test.mockwebserver.dispatcher.CombinedDispatcher;
import lombok.Setter;
import mockwebserver3.MockWebServer;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger(debug = JwksLoaderFactory.class)
@DisplayName("Tests JwksLoaderFactory functionality")
@EnableMockWebServer
class JwksLoaderFactoryTest implements MockWebServerHolder {

    private static final int REFRESH_INTERVAL_SECONDS = 1; // Short interval for testing
    private static final String TEST_KID = JWKSFactory.DEFAULT_KEY_ID;
    private final JwksResolveDispatcher testDispatcher = new JwksResolveDispatcher();
    @TempDir
    Path tempDir;
    @Setter
    private MockWebServer mockWebServer;
    private String httpJwksEndpoint;
    private Path fileJwksPath;
    private JwksResolveDispatcher jwksDispatcher;

    @Override
    public mockwebserver3.Dispatcher getDispatcher() {
        return new CombinedDispatcher().addDispatcher(testDispatcher);
    }

    @BeforeEach
    void setUp() throws IOException {
        // Setup HTTP endpoint
        int port = mockWebServer.getPort();
        httpJwksEndpoint = "http://localhost:" + port + JwksResolveDispatcher.LOCAL_PATH;
        jwksDispatcher = testDispatcher;
        jwksDispatcher.setCallCounter(0);

        // Setup file path
        fileJwksPath = tempDir.resolve("jwks.json");
        String jwksContent = JWKSFactory.createValidJwks();
        Files.writeString(fileJwksPath, jwksContent);
    }

    @Test
    @DisplayName("Should create HttpJwksLoader directly")
    void shouldCreateHttpJwksLoaderDirectly() {
        // When
        JwksLoader loader = JwksLoaderFactory.createHttpLoader(httpJwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        // Then
        Optional<Key> key = loader.getKey(TEST_KID);
        assertTrue(key.isPresent(), "Key should be present");
        assertEquals(1, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called once");
    }

    @Test
    @DisplayName("Should create FileJwksLoader directly")
    void shouldCreateFileJwksLoaderDirectly() {
        // When
        JwksLoader loader = JwksLoaderFactory.createFileLoader(fileJwksPath.toString());

        // Then
        Optional<Key> key = loader.getKey(TEST_KID);
        assertTrue(key.isPresent(), "Key should be present");
        assertEquals(0, jwksDispatcher.getCallCounter(), "JWKS endpoint should not be called");
    }

    @Test
    @DisplayName("Should throw exception when refresh interval is invalid")
    void shouldThrowExceptionWhenRefreshIntervalIsInvalid() {
        // When/Then
        assertThrows(IllegalArgumentException.class, () -> {
            JwksLoaderFactory.createHttpLoader(httpJwksEndpoint, 0, null);
        }, "Should throw exception when refresh interval is zero");

        assertThrows(IllegalArgumentException.class, () -> {
            JwksLoaderFactory.createHttpLoader(httpJwksEndpoint, -1, null);
        }, "Should throw exception when refresh interval is negative");
    }
}
