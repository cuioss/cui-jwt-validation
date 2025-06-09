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
