/*
 * Copyright 2023 the original author or authors.
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
package de.cuioss.jwt.token.flow;

import de.cuioss.jwt.token.JWTTokenLogMessages;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.annotation.Nonnull;
import lombok.Builder;

/**
 * Validator for JWT token headers.
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
     * Constructs a TokenHeaderValidator with the specified IssuerConfig.
     *
     * @param issuerConfig the issuer configuration
     */
    public TokenHeaderValidator(IssuerConfig issuerConfig) {
        this.issuerConfig = issuerConfig;
    }

    /**
     * Validates a decoded JWT token's header.     *
     *
     * @param decodedJwt the decoded JWT token to validate
     * @return true if the token header is valid, false otherwise.
     */
    public boolean validate(@Nonnull DecodedJwt decodedJwt) {
        LOGGER.trace("Validating token header");

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
     * Validates the token's algorithm against the configured algorithm preferences.
     *
     * @param decodedJwt the decoded JWT token
     * @return true if the algorithm is valid, false otherwise
     */
    private boolean validateAlgorithm(DecodedJwt decodedJwt) {
        var algorithm = decodedJwt.getAlg();

        if (algorithm.isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format("alg"));
            return false;
        }

        if (!issuerConfig.getAlgorithmPreferences().isSupported(algorithm.get())) {
            LOGGER.warn(JWTTokenLogMessages.WARN.UNSUPPORTED_ALGORITHM.format(algorithm.get()));
            return false;
        }

        LOGGER.debug("Algorithm is valid: %s", algorithm.get());
        return true;
    }

    /**
     * Validates the token's issuer against the configured expected issuers.
     *
     * @param decodedJwt the decoded JWT token
     * @return true if the issuer is valid, false otherwise
     */
    @SuppressWarnings("java:S3655") // Suppress warning for using Optional.get()
    // as we check for presence before calling it
    private boolean validateIssuer(DecodedJwt decodedJwt) {

        if (decodedJwt.getIssuer().isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format("iss"));
            return false;
        }
        var givenIssuer = decodedJwt.getIssuer().get();

        if (!issuerConfig.getIssuer().equals(givenIssuer)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.ISSUER_MISMATCH.format(givenIssuer, issuerConfig.getIssuer()));
            return false;
        }

        LOGGER.debug("Successfully validated issuer: %s", givenIssuer);
        return true;
    }
}
