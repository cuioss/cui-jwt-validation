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
package de.cuioss.jwt.quarkus.producer;

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.quarkus.config.TestConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Basic tests for {@link TokenValidatorProducer} using Quarkus test framework.
 */
@QuarkusTest
@EnableTestLogger
class QuarkusTokenValidatorProducerTest {

    @Inject
    TokenValidatorProducer producer;

    @Inject
    @TestConfig
    JwtValidationConfig testConfig;

    @Inject
    TokenValidator tokenValidator;

    /**
     * Test that the producer is properly injected.
     */
    @Test
    @DisplayName("Should inject the producer")
    void shouldInjectProducer() {
        // Assert
        assertNotNull(producer, "Producer should be injected");
        assertNotNull(testConfig, "Test config should be injected");
        assertNotNull(tokenValidator, "TokenValidator should be injected");
    }
}
