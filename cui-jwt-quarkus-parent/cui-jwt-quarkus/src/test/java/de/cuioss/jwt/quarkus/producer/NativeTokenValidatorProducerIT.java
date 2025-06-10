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

import de.cuioss.jwt.quarkus.config.JwtTestProfile;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Native image tests for the TokenValidatorProducer to verify it works properly in native mode.
 * This test validates that the producer correctly creates a TokenValidator that can validate tokens.
 */
@QuarkusIntegrationTest
@TestProfile(JwtTestProfile.class)
class NativeTokenValidatorProducerIT {

    @Inject
    TokenValidatorProducer producer;

    @Inject
    JwtValidationConfig config;

    @Inject
    TokenValidator tokenValidator;

    /**
     * Test that the producer and its dependencies are properly injected in native mode.
     */
    @Test
    @DisplayName("Should inject the producer in native mode")
    void shouldInjectProducer() {
        // Assert
        assertNotNull(producer, "Producer should be injected");
        assertNotNull(config, "Config should be injected");
        assertNotNull(tokenValidator, "TokenValidator should be injected");
    }

    /**
     * Test that the produced TokenValidator can validate tokens.
     */
    @Test
    @DisplayName("Should produce working TokenValidator in native mode")
    void shouldProduceWorkingTokenValidator() {
        // Given an empty token
        String emptyToken = "";

        // When validating the token with the produced TokenValidator
        // Then an exception should be thrown
        assertThrows(TokenValidationException.class, () -> tokenValidator.createAccessToken(emptyToken), "Produced TokenValidator should throw exception for empty token");
    }
}
