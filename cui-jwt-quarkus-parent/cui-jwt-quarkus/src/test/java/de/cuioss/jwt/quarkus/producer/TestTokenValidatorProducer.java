package de.cuioss.jwt.quarkus.producer;

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.quarkus.config.TestConfig;
import de.cuioss.jwt.validation.TokenValidator;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

/**
 * Test-specific producer for {@link TokenValidator} that uses the test configuration.
 * This allows the tests to run with a simplified configuration and without
 * requiring the full Quarkus configuration properties.
 */
@ApplicationScoped
@Alternative
public class TestTokenValidatorProducer {

    @Inject
    @TestConfig
    JwtValidationConfig testJwtValidationConfig;

    @Inject
    TokenValidatorProducer delegate;

    /**
     * Produces a TokenValidator instance using the test configuration.
     * This overrides the default production TokenValidator.
     * 
     * @return A TokenValidator configured for testing
     */
    @Produces
    @ApplicationScoped
    @Alternative
    public TokenValidator produceTestTokenValidator() {
        return delegate.getTokenValidator();
    }
}
