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
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.MockWebServerHolder;
import de.cuioss.test.mockwebserver.dispatcher.CombinedDispatcher;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import lombok.NonNull;
import lombok.Setter;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.util.Optional;

import static jakarta.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = JwksClient.class)
@DisplayName("Tests JwksClient factory functionality")
@EnableMockWebServer
class JwksClientTest implements MockWebServerHolder {

    private static final String JWKS_PATH = "/oidc/jwks.json";
    private static final int REFRESH_INTERVAL_SECONDS = 1; // Short interval for testing
    private static final String TEST_KID = JWKSFactory.TEST_KEY_ID;

    @Setter
    private MockWebServer mockWebServer;

    @TempDir
    Path tempDir;

    private String httpJwksEndpoint;
    private Path fileJwksPath;
    private JwksTestDispatcher jwksDispatcher;

    private final JwksTestDispatcher testDispatcher = new JwksTestDispatcher();

    @Override
    public mockwebserver3.Dispatcher getDispatcher() {
        return new CombinedDispatcher().addDispatcher(testDispatcher);
    }

    @BeforeEach
    void setUp() throws IOException {
        // Setup HTTP endpoint
        int port = mockWebServer.getPort();
        httpJwksEndpoint = "http://localhost:" + port + JWKS_PATH;
        jwksDispatcher = testDispatcher;
        jwksDispatcher.setCallCounter(0);

        // Setup file path
        fileJwksPath = tempDir.resolve("jwks.json");
        String jwksContent = JWKSFactory.createValidJwks();
        Files.writeString(fileJwksPath, jwksContent);
    }

    @Test
    @DisplayName("Should create HttpJwksLoader for HTTP URL")
    void shouldCreateHttpJwksLoaderForHttpUrl() {
        // When
        JwksClient client = new JwksClient(httpJwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        try {
            // Then
            Optional<Key> key = client.getKey(TEST_KID);
            assertTrue(key.isPresent(), "Key should be present");
            assertEquals(1, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called once");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Creating HttpJwksLoader for URL");
        } finally {
            client.shutdown();
        }
    }

    @Test
    @DisplayName("Should create FileJwksLoader for file path")
    void shouldCreateFileJwksLoaderForFilePath() {
        // When
        JwksClient client = new JwksClient(fileJwksPath.toString(), REFRESH_INTERVAL_SECONDS, null);

        try {
            // Then
            Optional<Key> key = client.getKey(TEST_KID);
            assertTrue(key.isPresent(), "Key should be present");
            assertEquals(0, jwksDispatcher.getCallCounter(), "JWKS endpoint should not be called");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Creating FileJwksLoader for path");
        } finally {
            client.shutdown();
        }
    }

    @Test
    @DisplayName("Should delegate getKey to loader")
    void shouldDelegateGetKeyToLoader() {
        // Given
        JwksClient client = new JwksClient(httpJwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        try {
            // When
            Optional<Key> key = client.getKey(TEST_KID);

            // Then
            assertTrue(key.isPresent(), "Key should be present");
            assertEquals(1, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called once");
        } finally {
            client.shutdown();
        }
    }

    @Test
    @DisplayName("Should delegate getFirstKey to loader")
    void shouldDelegateGetFirstKeyToLoader() {
        // Given
        JwksClient client = new JwksClient(httpJwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        try {
            // When
            Optional<Key> key = client.getFirstKey();

            // Then
            assertTrue(key.isPresent(), "Key should be present");
            assertEquals(1, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called once");
        } finally {
            client.shutdown();
        }
    }

    @Test
    @DisplayName("Should delegate refreshKeys to loader")
    void shouldDelegateRefreshKeysToLoader() {
        // Given
        JwksClient client = new JwksClient(httpJwksEndpoint, REFRESH_INTERVAL_SECONDS, null);
        // The endpoint is called once during initialization
        int initialCallCount = jwksDispatcher.getCallCounter();

        try {
            // When
            client.refreshKeys();

            // Then
            assertEquals(initialCallCount + 1, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called once more after refreshKeys");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Refreshing keys from JWKS endpoint");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Successfully refreshed keys");
        } finally {
            client.shutdown();
        }
    }

    @Test
    @DisplayName("Should delegate shutdown to loader")
    void shouldDelegateShutdownToLoader() {
        // Given
        JwksClient client = new JwksClient(httpJwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        // When
        client.shutdown();

        // Then
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Shutting down JwksClient");
    }

    @Test
    @DisplayName("Should use close method from AutoCloseable")
    void shouldUseCloseMethod() {
        // Given
        JwksClient client = new JwksClient(httpJwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        // When/Then
        // Verify that close method doesn't throw an exception
        assertDoesNotThrow(() -> client.close(), "close method should not throw an exception");
    }

    @Test
    @DisplayName("Should throw exception when refresh interval is invalid")
    void shouldThrowExceptionWhenRefreshIntervalIsInvalid() {
        // When/Then
        assertThrows(IllegalArgumentException.class, () -> {
            new JwksClient(httpJwksEndpoint, 0, null);
        }, "Should throw exception when refresh interval is zero");

        assertThrows(IllegalArgumentException.class, () -> {
            new JwksClient(httpJwksEndpoint, -1, null);
        }, "Should throw exception when refresh interval is negative");
    }

    /**
     * Test dispatcher that simulates a JWKS endpoint.
     */
    public static class JwksTestDispatcher implements ModuleDispatcherElement {

        private int callCounter = 0;

        public int getCallCounter() {
            return callCounter;
        }

        public void setCallCounter(int callCounter) {
            this.callCounter = callCounter;
        }

        private boolean returnError = false;

        public void setReturnError(boolean returnError) {
            this.returnError = returnError;
        }

        @Override
        public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
            callCounter++;

            if (returnError) {
                return Optional.of(new MockResponse(SC_INTERNAL_SERVER_ERROR, Headers.of(), ""));
            }

            String jwksJson = JWKSFactory.createValidJwks();

            return Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    jwksJson));
        }

        @Override
        public String getBaseUrl() {
            return JWKS_PATH;
        }
    }
}
