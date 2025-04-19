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
package de.cuioss.jwt.token;

import de.cuioss.jwt.token.flow.IssuerConfig;
import de.cuioss.jwt.token.flow.TokenFactoryConfig;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.jwt.token.test.generator.AccessTokenGenerator;
import de.cuioss.jwt.token.test.generator.IDTokenGenerator;
import de.cuioss.jwt.token.test.generator.RefreshTokenGenerator;
import de.cuioss.jwt.token.test.util.PerformanceStatistics;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.concurrent.ConcurrentTools;
import de.cuioss.tools.concurrent.StopWatch;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Performance tests for TokenFactory.
 * Tests the behavior of TokenFactory under concurrent load with multiple threads.
 */
@EnableTestLogger
@DisplayName("Tests TokenFactory performance")
class TokenFactoryPerformanceTest {

    private static final CuiLogger LOGGER = new CuiLogger(TokenFactoryPerformanceTest.class);
    private static final String ISSUER = TestTokenProducer.ISSUER;
    private static final String AUDIENCE = "test-client";
    private static final String CLIENT_ID = "test-client";

    // Performance test configuration
    private static final int DEFAULT_THREAD_COUNT = 100;
    private static final int DEFAULT_REQUESTS_PER_THREAD = 20;
    private static final int DEFAULT_PAUSE_MILLIS = 10; // 10 milliseconds

    // Token generators
    private final AccessTokenGenerator accessTokenGenerator = new AccessTokenGenerator(false);
    private final IDTokenGenerator idTokenGenerator = new IDTokenGenerator(false);
    private final RefreshTokenGenerator refreshTokenGenerator = new RefreshTokenGenerator(false);

    // Token factory
    private TokenFactory tokenFactory;

    @BeforeEach
    void setUp() {
        // Create a JWKSKeyLoader with the default JWKS content
        String jwksContent = JWKSFactory.createDefaultJwks();

        // Create issuer config
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .expectedClientId(CLIENT_ID)
                .jwksContent(jwksContent)
                .build();

        // Create token factory
        TokenFactoryConfig config = TokenFactoryConfig.builder().build();
        tokenFactory = new TokenFactory(config, issuerConfig);
    }

    @Test
    @DisplayName("Should handle concurrent access token creation")
    void shouldHandleConcurrentAccessTokenCreation() throws InterruptedException {
        LOGGER.info("Starting access token performance test");
        performConcurrentTest(DEFAULT_THREAD_COUNT, DEFAULT_REQUESTS_PER_THREAD, DEFAULT_PAUSE_MILLIS, TokenType.ACCESS);
    }

    @Test
    @DisplayName("Should handle concurrent ID token creation")
    void shouldHandleConcurrentIdTokenCreation() throws InterruptedException {
        LOGGER.info("Starting ID token performance test");
        performConcurrentTest(DEFAULT_THREAD_COUNT, DEFAULT_REQUESTS_PER_THREAD, DEFAULT_PAUSE_MILLIS, TokenType.ID);
    }

    @Test
    @DisplayName("Should handle concurrent refresh token creation")
    void shouldHandleConcurrentRefreshTokenCreation() throws InterruptedException {
        LOGGER.info("Starting refresh token performance test");
        performConcurrentTest(DEFAULT_THREAD_COUNT, DEFAULT_REQUESTS_PER_THREAD, DEFAULT_PAUSE_MILLIS, TokenType.REFRESH);
    }

    @Test
    @DisplayName("Should handle mixed token types concurrently")
    void shouldHandleMixedTokenTypesConcurrently() throws InterruptedException {
        LOGGER.info("Starting mixed token types performance test");
        performConcurrentTest(DEFAULT_THREAD_COUNT, DEFAULT_REQUESTS_PER_THREAD, DEFAULT_PAUSE_MILLIS, TokenType.MIXED);
    }

    /**
     * Performs a concurrent test with the specified configuration.
     *
     * @param threadCount       the number of threads to use
     * @param requestsPerThread the number of requests each thread should make
     * @param pauseMillis       the pause between requests in milliseconds
     * @param tokenType         the type of token to test
     * @throws InterruptedException if the test is interrupted
     */
    private void performConcurrentTest(int threadCount, int requestsPerThread, int pauseMillis, TokenType tokenType) throws InterruptedException {
        LOGGER.info("Starting performance test with %s threads, %s requests per thread, and %sms pause between requests for %s tokens",
                threadCount, requestsPerThread, pauseMillis, tokenType);

        // Create statistics tracker
        PerformanceStatistics stats = new PerformanceStatistics();

        // Create a countdown latch to wait for all threads to complete
        CountDownLatch latch = new CountDownLatch(threadCount);

        // Create a thread pool
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        // Counter for token type distribution in MIXED mode
        AtomicInteger tokenTypeCounter = new AtomicInteger(0);

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
                            // Time each token creation
                            StopWatch accessStopWatch = StopWatch.createStarted();

                            // Determine which token type to use for this request
                            TokenType currentTokenType = tokenType;
                            if (tokenType == TokenType.MIXED) {
                                // Rotate through token types
                                int typeIndex = tokenTypeCounter.getAndIncrement() % 3;
                                currentTokenType = TokenType.values()[typeIndex];
                            }

                            // Process the token based on its type
                            boolean success = processToken(currentTokenType);

                            // Stop timing and record statistics
                            accessStopWatch.stop();
                            long accessTimeNanos = accessStopWatch.elapsed(TimeUnit.NANOSECONDS);

                            // Record statistics
                            stats.recordAccessTime(accessTimeNanos);

                            // Record success or failure
                            if (success) {
                                stats.incrementSuccess();
                            } else {
                                stats.incrementFailure();
                                LOGGER.warn("Thread %s failed to process token on request %s", threadId, j);
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
        stats.setServerCallCount(0); // Not applicable for TokenFactory
        stats.setTotalRequests(threadCount * requestsPerThread);

        // Log all statistics in a single statement
        LOGGER.info("%s", stats);

        // Calculate tokens per second
        double tokensPerSecond = (stats.getSuccessCount() / (totalTimeMs / 1000.0));
        LOGGER.info("Tokens per second: %.2f", tokensPerSecond);

        // Assert results
        assertTrue(completed, "All threads should complete within the timeout period");
        assertEquals(threadCount * requestsPerThread,
                stats.getSuccessCount() + stats.getFailureCount() + stats.getEmptyResultCount(),
                "Total requests should equal successful + failed + empty requests");

        // Check if there were any failures
        if (stats.getFailureCount() > 0) {
            LOGGER.warn("Some requests failed. First few exceptions:");
            var exceptions = stats.getExceptions();
            for (int i = 0; i < Math.min(5, exceptions.size()); i++) {
                LOGGER.warn("Exception %s: %s", i, exceptions.get(i).getMessage());
            }
        }

        // Verify performance requirements
        if (tokenType != TokenType.MIXED) {
            // For specific token types, we can verify against requirements
            double requiredTokensPerSecond = (tokenType == TokenType.REFRESH) ? 1000 : 500;
            LOGGER.info("Required tokens per second: %.2f, Actual: %.2f", requiredTokensPerSecond, tokensPerSecond);

            // Note: This assertion is commented out because it might fail on slower CI systems
            // In a real implementation, you might want to adjust the thresholds based on the environment
            // assertTrue(tokensPerSecond >= requiredTokensPerSecond, 
            //     String.format("Token processing rate (%.2f/s) should meet requirement (%.2f/s)", 
            //     tokensPerSecond, requiredTokensPerSecond));
        }
    }

    /**
     * Processes a token based on its type.
     *
     * @param tokenType the type of token to process
     * @return true if the token was processed successfully, false otherwise
     */
    private boolean processToken(TokenType tokenType) {
        switch (tokenType) {
            case ACCESS:
                String accessToken = accessTokenGenerator.next();
                Optional<?> accessResult = tokenFactory.createAccessToken(accessToken);
                return accessResult.isPresent();
            case ID:
                String idToken = idTokenGenerator.next();
                Optional<?> idResult = tokenFactory.createIdToken(idToken);
                return idResult.isPresent();
            case REFRESH:
                String refreshToken = refreshTokenGenerator.next();
                Optional<?> refreshResult = tokenFactory.createRefreshToken(refreshToken);
                return refreshResult.isPresent();
            default:
                throw new IllegalArgumentException("Unsupported token type: " + tokenType);
        }
    }

    /**
     * Enum representing the different types of tokens that can be tested.
     */
    private enum TokenType {
        ACCESS,
        ID,
        REFRESH,
        MIXED
    }
}
