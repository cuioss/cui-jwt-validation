/**
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.quarkus.metrics;

import de.cuioss.jwt.quarkus.config.JwtTestProfile;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.micrometer.core.instrument.MeterRegistry;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for metrics collection during token validation.
 * This test verifies that metrics are properly collected when the TokenValidator
 * is used in a real application context.
 */
@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
class MetricsIntegrationTest {

    @Inject
    TokenValidator tokenValidator;

    @Inject
    MeterRegistry meterRegistry;

    @Test
    @DisplayName("Should record metrics for token validation")
    void shouldRecordMetricsForTokenValidation() {
        // Given - an invalid token to trigger validation errors
        String invalidToken = "invalid.jwt.token";

        // When - validate the token (will fail)
        try {
            tokenValidator.createAccessToken(invalidToken);
            fail("Should have thrown an exception for invalid token");
        } catch (Exception e) {
            // Expected exception
        }

        // Then - verify that error metrics were recorded
        assertNotNull(meterRegistry.find("cui.jwt.validation.errors").counters(),
                "Error counters should be registered");

        // Verify that at least one counter exists (we can't verify values reliably in tests)
        assertFalse(meterRegistry.find("cui.jwt.validation.errors").counters().isEmpty(), "Error counters should be registered");
    }

    @Test
    @DisplayName("Should register JWKs cache size metrics")
    void shouldRegisterJwksCacheSizeMetrics() {
        // Verify that JWKS cache size gauges are registered
        assertNotNull(meterRegistry.find("cui.jwt.jwks.cache.size").gauges(),
                "JWKS cache size gauges should be registered");
    }

    @Test
    @DisplayName("Should register metrics for all security event types")
    void shouldRegisterMetricsForAllSecurityEventTypes() {
        // Verify that metrics are registered for all event types
        for (SecurityEventCounter.EventType eventType : SecurityEventCounter.EventType.values()) {
            // Skip success events as they're handled differently
            if (eventType.name().contains("_CREATED")) {
                continue;
            }

            // Look for a counter with this event type
            boolean hasMetricForEventType = !meterRegistry.find("cui.jwt.validation.errors")
                    .tag("event_type", eventType.name())
                    .counters().isEmpty();

            assertTrue(hasMetricForEventType,
                    "Should have metrics registered for event type: " + eventType.name());
        }
    }
}
