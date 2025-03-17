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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static jakarta.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = {HttpJwksLoader.class, AbstractJwksLoader.class})
@DisplayName("Tests HttpJwksLoader functionality")
@EnableMockWebServer
class HttpJwksLoaderTest implements MockWebServerHolder {

    private static final String JWKS_PATH = "/oidc/jwks.json";
    private static final int REFRESH_INTERVAL_SECONDS = 1; // Short interval for testing
    private static final String TEST_KID = JWKSFactory.TEST_KEY_ID;

    @Setter
    private MockWebServer mockWebServer;

    private HttpJwksLoader httpJwksLoader;
    private String jwksEndpoint;
    private JwksTestDispatcher jwksDispatcher;

    private final JwksTestDispatcher testDispatcher = new JwksTestDispatcher();

    @Override
    public mockwebserver3.Dispatcher getDispatcher() {
        return new CombinedDispatcher().addDispatcher(testDispatcher);
    }

    @BeforeEach
    void setUp() {
        int port = mockWebServer.getPort();
        jwksEndpoint = "http://localhost:" + port + JWKS_PATH;
        jwksDispatcher = testDispatcher;
        jwksDispatcher.setCallCounter(0);
        httpJwksLoader = new HttpJwksLoader(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);
    }

    @AfterEach
    void tearDown() {
        if (httpJwksLoader != null) {
            httpJwksLoader.shutdown();
        }
    }

    @Test
    @DisplayName("Should fetch and parse JWKS from remote endpoint")
    void shouldFetchAndParseJwks() {
        // When
        Optional<Key> key = httpJwksLoader.getKey(TEST_KID);

        // Then
        assertTrue(key.isPresent(), "Key should be present");
        assertEquals(1, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called once");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Refreshing keys from JWKS endpoint");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Successfully refreshed");
    }

    @Test
    @DisplayName("Should cache keys and minimize HTTP requests")
    void shouldCacheKeys() {
        // When
        for (int i = 0; i < 5; i++) {
            Optional<Key> key = httpJwksLoader.getKey(TEST_KID);
            assertTrue(key.isPresent(), "Key should be present on call " + i);
        }

        // Then
        assertEquals(1, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called only once due to caching");
    }

    @Test
    @DisplayName("Should refresh keys when kid not found")
    void shouldRefreshKeysWhenKidNotFound() {
        // Given
        httpJwksLoader.getKey(TEST_KID); // Initial fetch
        assertEquals(1, jwksDispatcher.getCallCounter());

        // When
        jwksDispatcher.setReturnEmptyJwks(true);
        Optional<Key> key = httpJwksLoader.getKey("unknown-kid");

        // Then
        assertFalse(key.isPresent(), "Key should not be present");
        assertEquals(2, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called again");
    }

    @Test
    @DisplayName("Should handle server errors")
    void shouldHandleServerErrors() {
        // Given
        jwksDispatcher.setReturnError(true);

        // Create a new loader that will encounter server error
        HttpJwksLoader errorLoader = new HttpJwksLoader(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        try {
            // When
            Optional<Key> key = errorLoader.getKey(TEST_KID);

            // Then
            assertFalse(key.isPresent(), "Key should not be present when server returns error");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to fetch JWKS");
        } finally {
            errorLoader.shutdown();
        }
    }

    @Test
    @DisplayName("Should handle invalid JWKS format")
    void shouldHandleInvalidJwksFormat() {
        // Given
        jwksDispatcher.setReturnInvalidJson(true);

        // Create a new loader with invalid JSON response
        HttpJwksLoader invalidJsonLoader = new HttpJwksLoader(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        try {
            // When
            Optional<Key> key = invalidJsonLoader.getKey(TEST_KID);

            // Then
            assertFalse(key.isPresent(), "Key should not be present when JWKS is invalid");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse JWKS JSON");
        } finally {
            invalidJsonLoader.shutdown();
        }
    }

    @Test
    @DisplayName("Should refresh keys periodically")
    void shouldRefreshKeysPeriodically() throws InterruptedException {
        // Given
        httpJwksLoader.getKey(TEST_KID); // Initial fetch
        assertEquals(1, jwksDispatcher.getCallCounter());

        // When - wait for refresh interval
        TimeUnit.SECONDS.sleep(REFRESH_INTERVAL_SECONDS + 1);

        // Then - verify keys were refreshed automatically
        assertTrue(jwksDispatcher.getCallCounter() > 1, "JWKS endpoint should be called again after refresh interval");
    }

    @Test
    @DisplayName("Should return empty when kid is null")
    void shouldReturnEmptyWhenKidIsNull() {
        // When
        Optional<Key> key = httpJwksLoader.getKey(null);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when kid is null");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Key ID is null");
    }

    @Test
    @DisplayName("Should throw exception when refresh interval is invalid")
    void shouldThrowExceptionWhenRefreshIntervalIsInvalid() {
        // When/Then
        assertThrows(IllegalArgumentException.class, () -> {
            new HttpJwksLoader(jwksEndpoint, 0, null);
        }, "Should throw exception when refresh interval is zero");

        assertThrows(IllegalArgumentException.class, () -> {
            new HttpJwksLoader(jwksEndpoint, -1, null);
        }, "Should throw exception when refresh interval is negative");
    }

    @Test
    @DisplayName("Should handle missing required fields in JWK")
    void shouldHandleMissingRequiredFieldsInJwk() {
        // Given
        jwksDispatcher.setReturnMissingFieldsJwk(true);

        // Create a new loader with JWK missing required fields
        HttpJwksLoader missingFieldsLoader = new HttpJwksLoader(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        try {
            // When
            Optional<Key> key = missingFieldsLoader.getKey(TEST_KID);

            // Then
            assertFalse(key.isPresent(), "Key should not be present when JWK is missing required fields");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");
        } finally {
            missingFieldsLoader.shutdown();
        }
    }

    @Test
    @DisplayName("Should get first key when available")
    void shouldGetFirstKeyWhenAvailable() {
        // When
        Optional<Key> key = httpJwksLoader.getFirstKey();

        // Then
        assertTrue(key.isPresent(), "First key should be present");
    }

    @Test
    @DisplayName("Should handle invalid URL")
    void shouldHandleInvalidUrl() {
        // Given
        HttpJwksLoader invalidUrlLoader = new HttpJwksLoader("invalid-url", REFRESH_INTERVAL_SECONDS, null);

        try {
            // When
            Optional<Key> key = invalidUrlLoader.getKey(TEST_KID);

            // Then
            assertFalse(key.isPresent(), "Key should not be present when URL is invalid");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to fetch JWKS from URL: invalid-url");
        } finally {
            invalidUrlLoader.shutdown();
        }
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

        private boolean returnInvalidJson = false;

        public void setReturnInvalidJson(boolean returnInvalidJson) {
            this.returnInvalidJson = returnInvalidJson;
        }

        private boolean returnEmptyJwks = false;

        public void setReturnEmptyJwks(boolean returnEmptyJwks) {
            this.returnEmptyJwks = returnEmptyJwks;
        }

        private boolean returnMissingFieldsJwk = false;

        public void setReturnMissingFieldsJwk(boolean returnMissingFieldsJwk) {
            this.returnMissingFieldsJwk = returnMissingFieldsJwk;
        }

        @Override
        public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
            callCounter++;

            if (returnError) {
                return Optional.of(new MockResponse(SC_INTERNAL_SERVER_ERROR, Headers.of(), ""));
            }

            if (returnInvalidJson) {
                return Optional.of(new MockResponse(
                        SC_OK,
                        Headers.of("Content-Type", "application/json"),
                        JWKSFactory.createInvalidJson()));
            }

            String jwksJson;
            if (returnEmptyJwks) {
                jwksJson = JWKSFactory.createEmptyJwks();
            } else if (returnMissingFieldsJwk) {
                jwksJson = JWKSFactory.createJwksWithMissingFields(TEST_KID);
            } else {
                jwksJson = JWKSFactory.createValidJwks();
            }

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
