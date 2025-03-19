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
import de.cuioss.tools.logging.CuiLogger;
import lombok.Setter;
import mockwebserver3.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Simple benchmark test for JwksClient performance.
 * This is not a comprehensive benchmark, but provides basic performance metrics.
 */
@EnableTestLogger(debug = JwksLoaderFactory.class)
@DisplayName("Benchmarks JwksClient performance")
@EnableMockWebServer
public class JwksClientBenchmarkTest implements MockWebServerHolder {

    private static final CuiLogger LOGGER = new CuiLogger(JwksClientBenchmarkTest.class);
    private static final int REFRESH_INTERVAL_SECONDS = 60; // Longer interval for benchmarking
    private static final String TEST_KID = JWKSFactory.TEST_KEY_ID;
    private static final int WARMUP_ITERATIONS = 10;
    private static final int BENCHMARK_ITERATIONS = 100;

    @Setter
    private MockWebServer mockWebServer;

    private JwksLoader jwksLoader;
    private String jwksEndpoint;
    private JwksResolveDispatcher jwksDispatcher;

    private final JwksResolveDispatcher testDispatcher = new JwksResolveDispatcher();

    @Override
    public mockwebserver3.Dispatcher getDispatcher() {
        return new CombinedDispatcher().addDispatcher(testDispatcher);
    }

    @BeforeEach
    void setUp() {
        int port = mockWebServer.getPort();
        jwksEndpoint = "http://localhost:" + port + JwksResolveDispatcher.LOCAL_PATH;
        jwksDispatcher = testDispatcher;
        jwksLoader = JwksLoaderFactory.createHttpLoader(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);
    }

    @AfterEach
    void tearDown() {
        // No cleanup needed
    }

    @Test
    @DisplayName("Benchmark key retrieval performance")
    void benchmarkKeyRetrieval() {
        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            jwksLoader.getKey(TEST_KID);
        }

        // Benchmark
        long startTime = System.nanoTime();
        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            Optional<Key> key = jwksLoader.getKey(TEST_KID);
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
    @DisplayName("Benchmark key loader creation performance")
    void benchmarkKeyLoaderCreation() {
        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            JwksLoaderFactory.createHttpLoader(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);
        }

        // Benchmark
        long startTime = System.nanoTime();
        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            JwksLoader loader = JwksLoaderFactory.createHttpLoader(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);
            Optional<Key> key = loader.getKey(TEST_KID);
            assertTrue(key.isPresent(), "Key should be present");
        }
        long endTime = System.nanoTime();

        long durationNanos = endTime - startTime;
        double durationMillis = durationNanos / 1_000_000.0;
        double avgOperationTimeMillis = durationMillis / BENCHMARK_ITERATIONS;

        LOGGER.info("Key loader creation benchmark results:");
        LOGGER.info("Total time: %s ms", durationMillis);
        LOGGER.info("Average time per operation: %s ms", avgOperationTimeMillis);
        LOGGER.info("Operations per second: %s", (1000.0 / avgOperationTimeMillis));
    }
}