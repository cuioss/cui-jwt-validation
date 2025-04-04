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

import de.cuioss.jwt.token.jwks.key.KeyInfo;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcher;
import de.cuioss.tools.concurrent.StopWatch;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Simple benchmark test for JwksClient performance.
 * This is not a comprehensive benchmark, but provides basic performance metrics.
 */
@EnableTestLogger(debug = JwksLoaderFactory.class)
@DisplayName("Benchmarks JwksClient performance")
@EnableMockWebServer
class JwksClientBenchmarkTest {

    private static final CuiLogger LOGGER = new CuiLogger(JwksClientBenchmarkTest.class);
    private static final int REFRESH_INTERVAL_SECONDS = 60; // Longer interval for benchmarking
    private static final String TEST_KID = JWKSFactory.DEFAULT_KEY_ID;
    private static final int WARMUP_ITERATIONS = 10;
    private static final int BENCHMARK_ITERATIONS = 100;

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();


    @Test
    @DisplayName("Benchmark key retrieval performance")
    @ModuleDispatcher
    void benchmarkKeyRetrieval(URIBuilder uriBuilder) {
        var jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        var jwksLoader = JwksLoaderFactory.createHttpLoader(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);

        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            jwksLoader.getKeyInfo(TEST_KID).map(KeyInfo::getKey);
        }

        // Benchmark
        StopWatch watch = StopWatch.createStarted();
        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            Optional<Key> key = jwksLoader.getKeyInfo(TEST_KID).map(KeyInfo::getKey);
            assertTrue(key.isPresent(), "Key should be present");
        }
        watch.stop();

        double avgOperationTimeMillis = (double) watch.elapsed(TimeUnit.MILLISECONDS) / BENCHMARK_ITERATIONS;

        LOGGER.info("Key retrieval benchmark results:");
        LOGGER.info("Total time: %s ms", watch.toString());
        LOGGER.info("Average time per operation: %s ms", avgOperationTimeMillis);
        LOGGER.info("Operations per second: %s", (1000.0 / avgOperationTimeMillis));
    }

}
