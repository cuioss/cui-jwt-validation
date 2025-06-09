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
