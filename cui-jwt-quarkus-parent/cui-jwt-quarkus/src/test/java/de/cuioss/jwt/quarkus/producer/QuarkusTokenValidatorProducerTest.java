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
public class QuarkusTokenValidatorProducerTest {

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
