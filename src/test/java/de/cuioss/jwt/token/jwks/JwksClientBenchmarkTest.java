package de.cuioss.jwt.token.jwks;

import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.MockWebServerHolder;
import de.cuioss.test.mockwebserver.dispatcher.CombinedDispatcher;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import de.cuioss.tools.logging.CuiLogger;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Simple benchmark test for JwksClient performance.
 * This is not a comprehensive benchmark, but provides basic performance metrics.
 */
@EnableTestLogger(debug = JwksClient.class)
@DisplayName("Benchmarks JwksClient performance")
@EnableMockWebServer
public class JwksClientBenchmarkTest implements MockWebServerHolder {

    private static final CuiLogger LOGGER = new CuiLogger(JwksClientBenchmarkTest.class);
    private static final String JWKS_PATH = "/oidc/jwks.json";
    private static final int REFRESH_INTERVAL_SECONDS = 60; // Longer interval for benchmarking
    private static final String TEST_KID = "test-key-id";
    private static final int WARMUP_ITERATIONS = 10;
    private static final int BENCHMARK_ITERATIONS = 100;

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
        jwksClient = new JwksClient(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);
    }

    @AfterEach
    void tearDown() {
        if (jwksClient != null) {
            jwksClient.shutdown();
        }
    }

    @Test
    @DisplayName("Benchmark key retrieval performance")
    void benchmarkKeyRetrieval() {
        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            jwksClient.getKey(TEST_KID);
        }

        // Benchmark
        long startTime = System.nanoTime();
        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            Optional<Key> key = jwksClient.getKey(TEST_KID);
            assertTrue(key.isPresent(), "Key should be present");
        }
        long endTime = System.nanoTime();

        long durationNanos = endTime - startTime;
        double durationMillis = durationNanos / 1_000_000.0;
        double avgOperationTimeMillis = durationMillis / BENCHMARK_ITERATIONS;

        LOGGER.info("Key retrieval benchmark results:");
        LOGGER.info("Total time: %s ms", durationMillis);
        LOGGER.info("Average time per operation: %s ms", avgOperationTimeMillis);
        LOGGER.info("Operations per second: %s", (1000.0 / avgOperationTimeMillis));
    }

    @Test
    @DisplayName("Benchmark key refresh performance")
    void benchmarkKeyRefresh() {
        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            jwksClient.refreshKeys();
        }

        // Benchmark
        long startTime = System.nanoTime();
        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            jwksClient.refreshKeys();
        }
        long endTime = System.nanoTime();

        long durationNanos = endTime - startTime;
        double durationMillis = durationNanos / 1_000_000.0;
        double avgOperationTimeMillis = durationMillis / BENCHMARK_ITERATIONS;

        LOGGER.info("Key refresh benchmark results:");
        LOGGER.info("Total time: %s ms", durationMillis);
        LOGGER.info("Average time per operation: %s ms", avgOperationTimeMillis);
        LOGGER.info("Operations per second: %s", (1000.0 / avgOperationTimeMillis));
    }

    /**
     * Test dispatcher that simulates a JWKS endpoint.
     */
    public static class JwksTestDispatcher implements ModuleDispatcherElement {

        @Override
        public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
            String jwksJson = "{"
                    + "\"keys\": ["
                    + "  {"
                    + "    \"kid\": \"" + TEST_KID + "\","
                    + "    \"kty\": \"RSA\","
                    + "    \"n\": \"pBTkqmr5QeF3AN1e64t8z78ChaSuika4KWg1tV520qDEJk4BsWNzjcgTuHOFV0gQnG5c-p9gW7QOHZvq-FxTH4G64S01L3C9jGMqCODvYbm9Kv1Bc-gRwbXzfaue7PqPNSVK7xh5JQ4EqXgiGSbmnYQSrDGCQeV-NZevoxUL2yneRbgSl-cdazfi0qLn884hzysvr2NJwRWiWXooNzzPooRlvay4hHCkibbBnZpiOIMZFuXu4EGrwD24qZmPzQL_LoIT_BAv5ZyNGmsIvqdMKpCYfQrO2VAHifa05VSZJfwdXlYxPL815hxIGWHYKHTiuoZrdJ9fcebN9x2cAEGAYw\","
                    + "    \"e\": \"AQAB\""
                    + "  }"
                    + "]"
                    + "}";

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
