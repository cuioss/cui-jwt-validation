/*
 * Copyright 2025 the original author or authors.
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
package de.cuioss.jwt.validation.flow;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.JWTValidationLogMessages;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.annotation.Nonnull;
import lombok.Builder;
import lombok.NonNull;

/**
 * Validator for JWT validation headers.
 * <p>
 * This class validates the following header elements:
 * <ul>
 *   <li>Algorithm (alg) - against configured AlgorithmPreferences</li>
 *   <li>Issuer (iss) - against configured expected issuer</li>
 * </ul>
 * <p>
 * The validator logs appropriate warning messages for validation failures.
 */
@Builder
public class TokenHeaderValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenHeaderValidator.class);

    private final IssuerConfig issuerConfig;
    /**
     * The counter for security events.
     */
    @NonNull
    private final SecurityEventCounter securityEventCounter;

    /**
     * Constructs a TokenHeaderValidator with the specified IssuerConfig.
     *
     * @param issuerConfig         the issuer configuration
     * @param securityEventCounter the counter for security events
     */
    public TokenHeaderValidator(IssuerConfig issuerConfig, @NonNull SecurityEventCounter securityEventCounter) {
        this.issuerConfig = issuerConfig;
        this.securityEventCounter = securityEventCounter;
    }


    /**
     * Validates a decoded JWT validation's header.     *
     *
     * @param decodedJwt the decoded JWT validation to validate
     * @return true if the validation header is valid, false otherwise.
     */
    public boolean validate(@Nonnull DecodedJwt decodedJwt) {
        LOGGER.trace("Validating validation header");

        if (!validateAlgorithm(decodedJwt)) {
            return false;
        }

        if (!validateIssuer(decodedJwt)) {
            return false;
        }

        LOGGER.debug("Token header is valid");
        return true;
    }

    /**
     * Validates the validation's algorithm against the configured algorithm preferences.
     *
     * @param decodedJwt the decoded JWT validation
     * @return true if the algorithm is valid, false otherwise
     */
    private boolean validateAlgorithm(DecodedJwt decodedJwt) {
        var algorithm = decodedJwt.getAlg();

        if (algorithm.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM.format("alg"));
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            return false;
        }

        if (!issuerConfig.getAlgorithmPreferences().isSupported(algorithm.get())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.UNSUPPORTED_ALGORITHM.format(algorithm.get()));
            securityEventCounter.increment(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);
            return false;
        }

        LOGGER.debug("Algorithm is valid: %s", algorithm.get());
        return true;
    }

    /**
     * Validates the validation's issuer against the configured expected issuers.
     *
     * @param decodedJwt the decoded JWT validation
     * @return true if the issuer is valid, false otherwise
     */
    @SuppressWarnings("java:S3655") // Suppress warning for using Optional.get()
    // as we check for presence before calling it
    private boolean validateIssuer(DecodedJwt decodedJwt) {

        if (decodedJwt.getIssuer().isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM.format("iss"));
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            return false;
        }
        var givenIssuer = decodedJwt.getIssuer().get();

        if (!issuerConfig.getIssuer().equals(givenIssuer)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.ISSUER_MISMATCH.format(givenIssuer, issuerConfig.getIssuer()));
            securityEventCounter.increment(SecurityEventCounter.EventType.ISSUER_MISMATCH);
            return false;
        }

        LOGGER.debug("Successfully validated issuer: %s", givenIssuer);
        return true;
    }
}
