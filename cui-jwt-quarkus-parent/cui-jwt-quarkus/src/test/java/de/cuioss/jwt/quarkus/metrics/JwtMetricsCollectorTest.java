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

import de.cuioss.jwt.quarkus.config.JwtPropertyKeys;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.security.SecurityEventCounter.EventType;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link JwtMetricsCollector}.
 */
@QuarkusTest
class JwtMetricsCollectorTest {

    @Inject
    TokenValidator tokenValidator;

    @Inject
    MeterRegistry registry;

    @Inject
    JwtMetricsCollector metricsCollector;

    @Inject
    Event<StartupEvent> startupEvent;

    @Test
    void shouldInitializeMetrics() {
        // Ensure collector is properly initialized
        assertNotNull(metricsCollector);

        // Get counters from registry
        Collection<Counter> counters = registry.find(JwtPropertyKeys.METRICS.VALIDATION_ERRORS).counters();

        // Verify counters exist for all event types
        assertFalse(counters.isEmpty(), "Should have registered counters");

        // Verify all event types have corresponding counters
        for (EventType eventType : SecurityEventCounter.EventType.values()) {
            boolean hasCounter = counters.stream()
                    .anyMatch(counter -> Objects.equals(counter.getId().getTag("event_type"), eventType.name()));
            assertTrue(hasCounter, "Should have counter for event type: " + eventType.name());
        }
    }

    @Test
    void shouldHaveMetricsForSecurityEvents() {
        // Fire the startup event to ensure metrics are initialized
        startupEvent.fire(new StartupEvent());

        // Get the security event counter from the token validator
        SecurityEventCounter counter = tokenValidator.getSecurityEventCounter();
        assertNotNull(counter);

        // Record some events
        EventType testEventType = EventType.SIGNATURE_VALIDATION_FAILED;
        counter.increment(testEventType);
        counter.increment(testEventType);

        // Manually update counters (instead of waiting for scheduled update)
        metricsCollector.updateCounters();

        // Verify the metric exists with the correct tags
        boolean hasMetric = !registry.find(JwtPropertyKeys.METRICS.VALIDATION_ERRORS)
                .tag("event_type", testEventType.name())
                .tag("result", "failure")
                .tag("category", "INVALID_SIGNATURE")
                .counters().isEmpty();

        assertTrue(hasMetric, "Should have metric for the event type");
    }
}
