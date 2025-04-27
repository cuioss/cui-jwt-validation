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
package de.cuioss.jwt.validation.jwks.http;

import de.cuioss.jwt.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.validation.test.JWKSFactory;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.concurrent.ConcurrentTools;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests JwksCacheManager")
class JwksCacheManagerTest {

    private static final String JWKS_CONTENT = JWKSFactory.createDefaultJwks();
    private static final String ETAG = "\"test-etag\"";
    private static final String JWKS_URI = "https://example.com/.well-known/jwks.json";
    private static final int REFRESH_INTERVAL = 60;

    private HttpJwksLoaderConfig config;
    private JwksCacheManager cacheManager;
    private AtomicInteger loaderCallCount;

    @BeforeEach
    void setUp() {
        config = HttpJwksLoaderConfig.builder()
                .jwksUrl(JWKS_URI)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        loaderCallCount = new AtomicInteger(0);

        Function<String, JWKSKeyLoader> cacheLoader = key -> {
            loaderCallCount.incrementAndGet();
            return new JWKSKeyLoader(JWKS_CONTENT, ETAG);
        };

        cacheManager = new JwksCacheManager(config, cacheLoader);
    }

    @Test
    @DisplayName("Should create cache manager with config")
    void shouldCreateCacheManagerWithConfig() {
        // Then
        assertNotNull(cacheManager);
        assertEquals(CACHE_KEY_PREFIX + JWKS_URI, cacheManager.getCacheKey());
    }

    @Test
    @DisplayName("Should cache results")
    void shouldCacheResults() {
        // When
        JWKSKeyLoader result1 = cacheManager.resolve();
        JWKSKeyLoader result2 = cacheManager.resolve();

        // Then
        assertNotNull(result1);
        assertNotNull(result2);
        assertEquals(1, loaderCallCount.get(), "Cache loader should be called only once");
        assertSame(result1, result2, "Cached results should be the same instance");
    }

    @Test
    @DisplayName("Should update cache with new content")
    void shouldUpdateCacheWithNewContent() {
        // Given
        String newContent = JWKSFactory.createDefaultJwks(); // Different instance but same content
        String newEtag = "\"new-etag\"";

        // When
        JWKSKeyLoader initialResult = cacheManager.resolve();
        JwksCacheManager.KeyRotationResult result = cacheManager.updateCache(newContent, newEtag);
        JWKSKeyLoader updatedResult = result.getKeyLoader();

        // Then
        assertNotNull(initialResult);
        assertNotNull(updatedResult);
        assertEquals(newEtag, cacheManager.getCurrentEtag());

        // Verify that the last valid result is updated
        Optional<JWKSKeyLoader> lastValidResult = cacheManager.getLastValidResult();
        assertTrue(lastValidResult.isPresent(), "Last valid result should be present after update");
        assertSame(updatedResult, lastValidResult.get(), "Last valid result should be the updated result");
    }

    @Test
    @DisplayName("Should handle not modified response")
    void shouldHandleNotModifiedResponse() {
        // Given
        // First, update the cache to set the lastValidResult
        JwksCacheManager.KeyRotationResult result = cacheManager.updateCache(JWKS_CONTENT, ETAG);
        JWKSKeyLoader initialResult = result.getKeyLoader();

        // When
        JWKSKeyLoader notModifiedResult = cacheManager.handleNotModified();

        // Then
        assertNotNull(initialResult);
        assertNotNull(notModifiedResult);
        assertSame(initialResult, notModifiedResult, "Not modified result should be the same as initial result");
    }

    @Test
    @DisplayName("Should refresh cache")
    void shouldRefreshCache() {
        // Given
        JWKSKeyLoader initialResult = cacheManager.resolve();
        int initialCallCount = loaderCallCount.get();

        // When
        cacheManager.refresh();
        JWKSKeyLoader refreshedResult = cacheManager.resolve();

        // Then
        assertNotNull(initialResult);
        assertNotNull(refreshedResult);
        // Starting with Java 21 wie nee a slight delay here.
        ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(100));
        assertTrue(loaderCallCount.get() > initialCallCount, "Cache loader should be called again after refresh");
    }

    @Test
    @DisplayName("Should return last valid result when loader throws exception")
    void shouldReturnLastValidResultWhenLoaderThrowsException() {

        // Create a new cache manager with a loader that throws an exception
        Function<String, JWKSKeyLoader> failingLoader = key -> {
            throw new RuntimeException("Test exception");
        };

        JwksCacheManager failingCacheManager = new JwksCacheManager(config, failingLoader);

        // Set the last valid result
        failingCacheManager.updateCache(JWKS_CONTENT, ETAG);

        // When
        JWKSKeyLoader result = failingCacheManager.resolve();

        // Then
        assertNotNull(result);
        assertTrue(result.isNotEmpty(), "Result should not be empty");
    }

    @Test
    @DisplayName("Should return empty result when no last valid result and loader throws exception")
    void shouldReturnEmptyResultWhenNoLastValidResultAndLoaderThrowsException() {
        // Given
        // Create a cache manager with a loader that throws an exception
        Function<String, JWKSKeyLoader> failingLoader = key -> {
            throw new RuntimeException("Test exception");
        };

        JwksCacheManager failingCacheManager = new JwksCacheManager(config, failingLoader);

        // When
        JWKSKeyLoader result = failingCacheManager.resolve();

        // Then
        assertNotNull(result);
        assertFalse(result.isNotEmpty(), "Result should be empty");
    }

    @Test
    @DisplayName("Should get last valid result")
    void shouldGetLastValidResult() {
        // Given
        // Initially there is no last valid result
        Optional<JWKSKeyLoader> initialLastValidResult = cacheManager.getLastValidResult();

        // When
        // Update the cache to set the lastValidResult
        JwksCacheManager.KeyRotationResult rotationResult = cacheManager.updateCache(JWKS_CONTENT, ETAG);
        JWKSKeyLoader updatedResult = rotationResult.getKeyLoader();
        Optional<JWKSKeyLoader> lastValidResult = cacheManager.getLastValidResult();

        // Then
        assertFalse(initialLastValidResult.isPresent(), "Initial last valid result should be empty");
        assertTrue(lastValidResult.isPresent(), "Last valid result should be present after update");
        assertSame(updatedResult, lastValidResult.get(), "Last valid result should be the same as updated result");
    }

    // Private constant for testing
    private static final String CACHE_KEY_PREFIX = "jwks:";
}
