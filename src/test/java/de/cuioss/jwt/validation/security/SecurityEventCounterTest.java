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
package de.cuioss.jwt.validation.security;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for {@link SecurityEventCounter}.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li>CUI-JWT-7.1: Security Event Monitoring</li>
 *   <li>CUI-JWT-7.2: Security Event Tracking</li>
 *   <li>CUI-JWT-7.3: Thread-Safe Monitoring</li>
 * </ul>
 * <p>
 * This test class ensures that security events are properly counted, can be reset,
 * and that the counter implementation is thread-safe for concurrent access.
 *
 * @author Oliver Wolff
 * @see <a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/specification/security.adoc#security-controls">Security Controls Specification</a>
 */
class SecurityEventCounterTest {

    @Test
    void shouldIncrementCounter() {
        // Given
        SecurityEventCounter counter = new SecurityEventCounter();

        // When
        long count = counter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);

        // Then
        assertEquals(1, count);
        assertEquals(1, counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
    }

    @Test
    void shouldReturnZeroForNonExistingCounter() {
        // Given
        SecurityEventCounter counter = new SecurityEventCounter();

        // When
        long count = counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY);

        // Then
        assertEquals(0, count);
    }

    @Test
    void shouldResetAllCounters() {
        // Given
        SecurityEventCounter counter = new SecurityEventCounter();
        counter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
        counter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);

        // When
        counter.reset();

        // Then
        assertEquals(0, counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
        assertEquals(0, counter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
    }

    @Test
    void shouldResetSpecificCounter() {
        // Given
        SecurityEventCounter counter = new SecurityEventCounter();
        counter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
        counter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);

        // When
        counter.reset(SecurityEventCounter.EventType.TOKEN_EMPTY);

        // Then
        assertEquals(0, counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
        assertEquals(1, counter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
    }

    @Test
    void shouldGetAllCounters() {
        // Given
        SecurityEventCounter counter = new SecurityEventCounter();
        counter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
        counter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
        counter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);

        // When
        Map<SecurityEventCounter.EventType, Long> counters = counter.getCounters();

        // Then
        assertEquals(2, counters.size());
        assertEquals(1L, counters.get(SecurityEventCounter.EventType.TOKEN_EMPTY));
        assertEquals(2L, counters.get(SecurityEventCounter.EventType.MISSING_CLAIM));
    }

    @Test
    void shouldBeThreadSafe() throws InterruptedException {
        // Given
        final int threadCount = 10;
        final int incrementsPerThread = 1000;
        final SecurityEventCounter counter = new SecurityEventCounter();
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch endLatch = new CountDownLatch(threadCount);
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        // When
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await(); // Wait for all threads to be ready
                    for (int j = 0; j < incrementsPerThread; j++) {
                        counter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    endLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // Start all threads
        boolean completed = endLatch.await(10, TimeUnit.SECONDS); // Wait for all threads to complete
        executor.shutdown();

        // Then
        assertTrue(completed, "All threads should have completed");
        assertEquals(threadCount * incrementsPerThread, counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
    }
}