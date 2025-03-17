package de.cuioss.jwt.token.jwks;

import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.MockWebServerHolder;
import de.cuioss.test.mockwebserver.dispatcher.CombinedDispatcher;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import de.cuioss.tools.io.FileLoaderUtility;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;
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

import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static jakarta.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = JwksClient.class)
@DisplayName("Tests JwksClient functionality")
@EnableMockWebServer
public class JwksClientTest implements MockWebServerHolder {

    private static final CuiLogger LOGGER = new CuiLogger(JwksClientTest.class);
    private static final String JWKS_PATH = "/oidc/jwks.json";
    private static final int REFRESH_INTERVAL_SECONDS = 1; // Short interval for testing
    private static final String TEST_KID = "test-key-id";

    @Setter
    private MockWebServer mockWebServer;

    private JwksClient jwksClient;
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
        jwksClient = new JwksClient(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);
    }

    @AfterEach
    void tearDown() {
        if (jwksClient != null) {
            jwksClient.shutdown();
        }
    }

    @Test
    @DisplayName("Should fetch and parse JWKS from remote endpoint")
    void shouldFetchAndParseJwks() {
        // When
        Optional<Key> key = jwksClient.getKey(TEST_KID);

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
            Optional<Key> key = jwksClient.getKey(TEST_KID);
            assertTrue(key.isPresent(), "Key should be present on call " + i);
        }

        // Then
        assertEquals(1, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called only once due to caching");
    }

    @Test
    @DisplayName("Should refresh keys when kid not found")
    void shouldRefreshKeysWhenKidNotFound() {
        // Given
        jwksClient.getKey(TEST_KID); // Initial fetch
        assertEquals(1, jwksDispatcher.getCallCounter());

        // When
        jwksDispatcher.setReturnEmptyJwks(true);
        Optional<Key> key = jwksClient.getKey("unknown-kid");

        // Then
        assertFalse(key.isPresent(), "Key should not be present");
        assertEquals(2, jwksDispatcher.getCallCounter(), "JWKS endpoint should be called again");
    }

    @Test
    @DisplayName("Should handle server errors")
    void shouldHandleServerErrors() {
        // Given
        jwksDispatcher.setReturnError(true);

        // Create a new client that will encounter server error
        JwksClient errorClient = new JwksClient(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        try {
            // When
            Optional<Key> key = errorClient.getKey(TEST_KID);

            // Then
            assertFalse(key.isPresent(), "Key should not be present when server returns error");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to fetch JWKS: HTTP 500");
        } finally {
            errorClient.shutdown();
        }
    }

    @Test
    @DisplayName("Should handle invalid JWKS format")
    void shouldHandleInvalidJwksFormat() {
        // Given
        jwksDispatcher.setReturnInvalidJson(true);

        // Create a new client with invalid JSON response
        JwksClient invalidJsonClient = new JwksClient(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        try {
            // When
            Optional<Key> key = invalidJsonClient.getKey(TEST_KID);

            // Then
            assertFalse(key.isPresent(), "Key should not be present when JWKS is invalid");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse JWKS JSON");
        } finally {
            invalidJsonClient.shutdown();
        }
    }

    @Test
    @DisplayName("Should refresh keys periodically")
    void shouldRefreshKeysPeriodically() throws InterruptedException {
        // Given
        jwksClient.getKey(TEST_KID); // Initial fetch
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
        Optional<Key> key = jwksClient.getKey(null);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when kid is null");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Key ID is null");
    }

    @Test
    @DisplayName("Should throw exception when refresh interval is invalid")
    void shouldThrowExceptionWhenRefreshIntervalIsInvalid() {
        // When/Then
        assertThrows(IllegalArgumentException.class, () -> {
            new JwksClient(jwksEndpoint, 0, null);
        }, "Should throw exception when refresh interval is zero");

        assertThrows(IllegalArgumentException.class, () -> {
            new JwksClient(jwksEndpoint, -1, null);
        }, "Should throw exception when refresh interval is negative");
    }

    @Test
    @DisplayName("Should use close method from AutoCloseable")
    void shouldUseCloseMethod() {
        // Given
        JwksClient client = new JwksClient(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        // When
        try (JwksClient autoCloseableClient = client) {
            // Use in try-with-resources
        }

        // Then
        // Verify client was shut down by checking logs
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Shutting down JwksClient");
    }

    @Test
    @DisplayName("Should handle missing required fields in JWK")
    void shouldHandleMissingRequiredFieldsInJwk() {
        // Given
        jwksDispatcher.setReturnMissingFieldsJwk(true);

        // Create a new client with JWK missing required fields
        JwksClient missingFieldsClient = new JwksClient(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        try {
            // When
            Optional<Key> key = missingFieldsClient.getKey(TEST_KID);

            // Then
            assertFalse(key.isPresent(), "Key should not be present when JWK is missing required fields");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");
        } finally {
            missingFieldsClient.shutdown();
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
                        "invalid json"));
            }

            String jwksJson;
            if (returnEmptyJwks) {
                jwksJson = "{\"keys\": []}";
            } else if (returnMissingFieldsJwk) {
                jwksJson = "{"
                        + "\"keys\": ["
                        + "  {"
                        + "    \"kid\": \"" + TEST_KID + "\","
                        + "    \"kty\": \"RSA\""
                        + "  }"
                        + "]"
                        + "}";
            } else {
                jwksJson = "{"
                        + "\"keys\": ["
                        + "  {"
                        + "    \"kid\": \"" + TEST_KID + "\","
                        + "    \"kty\": \"RSA\","
                        + "    \"n\": \"pBTkqmr5QeF3AN1e64t8z78ChaSuika4KWg1tV520qDEJk4BsWNzjcgTuHOFV0gQnG5c-p9gW7QOHZvq-FxTH4G64S01L3C9jGMqCODvYbm9Kv1Bc-gRwbXzfaue7PqPNSVK7xh5JQ4EqXgiGSbmnYQSrDGCQeV-NZevoxUL2yneRbgSl-cdazfi0qLn884hzysvr2NJwRWiWXooNzzPooRlvay4hHCkibbBnZpiOIMZFuXu4EGrwD24qZmPzQL_LoIT_BAv5ZyNGmsIvqdMKpCYfQrO2VAHifa05VSZJfwdXlYxPL815hxIGWHYKHTiuoZrdJ9fcebN9x2cAEGAYw\","
                        + "    \"e\": \"AQAB\""
                        + "  }"
                        + "]"
                        + "}";
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
