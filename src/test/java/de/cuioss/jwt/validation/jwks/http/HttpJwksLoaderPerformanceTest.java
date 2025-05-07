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
package de.cuioss.jwt.validation.jwks.http;

import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.dispatcher.EnhancedJwksResolveDispatcher;
import de.cuioss.jwt.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.jwt.validation.test.util.PerformanceStatistics;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.test.mockwebserver.dispatcher.CombinedDispatcher;
import de.cuioss.tools.concurrent.ConcurrentTools;
import de.cuioss.tools.concurrent.StopWatch;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Performance tests for HttpJwksLoader.
 * Tests the behavior of HttpJwksLoader under concurrent load with multiple threads.
 */
@EnableTestLogger(warn = CombinedDispatcher.class)
@DisplayName("Tests HttpJwksLoader performance")
@EnableMockWebServer
class HttpJwksLoaderPerformanceTest {

    private static final CuiLogger LOGGER = new CuiLogger(HttpJwksLoaderPerformanceTest.class);
    private static final int REFRESH_INTERVAL_SECONDS = 1; // Short interval for testing
    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final String NON_EXISTENT_KID = "non-existent-kid";

    // Performance test configuration
    private static final int DEFAULT_THREAD_COUNT = 250;
    private static final int DEFAULT_REQUESTS_PER_THREAD = 50;
    private static final int DEFAULT_PAUSE_MILLIS = 1000; // 1 second

    @Getter
    private final EnhancedJwksResolveDispatcher moduleDispatcher = new EnhancedJwksResolveDispatcher();
    private HttpJwksLoader httpJwksLoader;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        // Initialize the SecurityEventCounter
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .build();

        httpJwksLoader = new HttpJwksLoader(config, securityEventCounter);
    }

    @Test
    @DisplayName("Should handle concurrent access from multiple threads")
    void shouldHandleConcurrentAccess() throws InterruptedException {
        performConcurrentTest(DEFAULT_THREAD_COUNT, DEFAULT_REQUESTS_PER_THREAD, DEFAULT_PAUSE_MILLIS);
    }

    /**
     * Performs a concurrent test with the specified configuration.
     *
     * @param threadCount       the number of threads to use
     * @param requestsPerThread the number of requests each thread should make
     * @param pauseMillis       the pause between requests in milliseconds
     * @throws InterruptedException if the test is interrupted
     */
    private void performConcurrentTest(int threadCount, int requestsPerThread, int pauseMillis) throws InterruptedException {
        LOGGER.info("Starting performance test with %s threads, %s requests per thread, and %sms pause between requests",
                threadCount, requestsPerThread, pauseMillis);

        // Create statistics tracker
        PerformanceStatistics stats = new PerformanceStatistics();

        // Create a countdown latch to wait for all threads to complete
        CountDownLatch latch = new CountDownLatch(threadCount);

        // Create a thread pool
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        // Start overall timing
        StopWatch overallStopWatch = StopWatch.createStarted();

        // Submit tasks to the thread pool
        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    LOGGER.debug("Thread %s started", threadId);

                    for (int j = 0; j < requestsPerThread; j++) {
                        try {
                            // Time each key info access
                            StopWatch accessStopWatch = StopWatch.createStarted();

                            // For every tenth thread, load a non-existent key
                            String kidToUse = (threadId % 10 == 0) ? NON_EXISTENT_KID : TEST_KID;

                            // Request the key info
                            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(kidToUse);

                            // Stop timing and record statistics
                            accessStopWatch.stop();
                            long accessTimeNanos = accessStopWatch.elapsed(TimeUnit.NANOSECONDS);

                            // Record statistics
                            stats.recordAccessTime(accessTimeNanos);

                            // Verify the result - only count as failure if it's not a tenth thread with non-existent key
                            if (keyInfo.isPresent()) {
                                stats.incrementSuccess();
                            } else if (threadId % 10 == 0) {
                                // This is expected for every tenth thread, don't count as error
                                stats.incrementEmptyResult();
                            } else {
                                stats.incrementFailure();
                                LOGGER.warn("Thread %s failed to get key info on request %s", threadId, j);
                            }

                            // Pause between requests
                            if (j < requestsPerThread - 1) { // Don't pause after the last request
                                ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(pauseMillis));
                            }
                        } catch (Exception e) {
                            stats.incrementFailure();
                            stats.addException(e);
                            LOGGER.warn("Thread %s encountered exception on request %s: %s", threadId, j, e.getMessage());
                        }
                    }

                    LOGGER.debug("Thread %s completed all requests", threadId);
                } finally {
                    latch.countDown();
                }
            });
        }

        // Wait for all threads to complete or timeout after a reasonable period
        boolean completed = latch.await(threadCount * requestsPerThread * pauseMillis * 2L, TimeUnit.MILLISECONDS);

        // Shutdown the executor
        executor.shutdown();
        boolean terminated = executor.awaitTermination(5, TimeUnit.SECONDS);

        // Stop overall timing
        overallStopWatch.stop();
        long totalTimeMs = overallStopWatch.elapsed(TimeUnit.MILLISECONDS);

        // Set final statistics
        stats.setTotalTimeMs(totalTimeMs);
        stats.setCompleted(completed);
        stats.setTerminated(terminated);
        stats.setServerCallCount(moduleDispatcher.getCallCounter());
        stats.setTotalRequests(threadCount * requestsPerThread);

        // Log all statistics in a single statement
        LOGGER.info("%s", stats);

        // Assert results
        assertTrue(completed, "All threads should complete within the timeout period");
        assertEquals(threadCount * requestsPerThread,
                stats.getSuccessCount() + stats.getFailureCount() + stats.getEmptyResultCount(),
                "Total requests should equal successful + failed + empty requests");
        assertTrue(stats.getSuccessCount() > 0, "There should be at least some successful requests");

        // Check if there were any failures
        if (stats.getFailureCount() > 0) {
            LOGGER.warn("Some requests failed. First few exceptions:");
            List<Throwable> exceptions = stats.getExceptions();
            for (int i = 0; i < Math.min(5, exceptions.size()); i++) {
                LOGGER.warn("Exception %s: %s", i, exceptions.get(i).getMessage());
            }
        }

        // Assert that all requests were successful (counting expected empty results as successful)
        double successRate = (double) (stats.getSuccessCount() + stats.getEmptyResultCount()) / stats.getTotalRequests() * 100;
        assertEquals(100.0, successRate, "Success rate must be 100%");

        // Verify the call counter to ensure the server was actually called
        int expectedMinimumCalls = 1; // At minimum, we expect the initial call to populate the cache
        assertTrue(moduleDispatcher.getCallCounter() >= expectedMinimumCalls,
                "Server should be called at least " + expectedMinimumCalls + " times");
    }

}
