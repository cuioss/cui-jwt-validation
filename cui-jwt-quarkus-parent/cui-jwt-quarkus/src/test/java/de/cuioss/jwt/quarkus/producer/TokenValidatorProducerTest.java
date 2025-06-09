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

import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Basic tests for {@link TokenValidatorProducer}.
 */
@EnableTestLogger
class TokenValidatorProducerTest {

    /**
     * Test that the TokenValidatorProducer can be instantiated.
     */
    @Test
    @DisplayName("Should instantiate the producer")
    void shouldInstantiateProducer() {
        // Arrange & Act
        TokenValidatorProducer producer = new TokenValidatorProducer();

        // Assert
        assertNotNull(producer, "Producer should be instantiated");
    }
}
