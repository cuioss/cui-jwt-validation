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
import de.cuioss.jwt.token.security.AlgorithmPreferences;
import de.cuioss.tools.collect.MoreCollections;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.annotation.Nonnull;
import lombok.Builder;
import lombok.Getter;
import lombok.Singular;

import java.util.Set;

/**
 * Validator for JWT token headers.
 * <p>
 * This class validates the following header elements:
 * <ul>
 *   <li>Algorithm (alg) - against configured AlgorithmPreferences</li>
 *   <li>Issuer (iss) - against configured expected issuers</li>
 * </ul>
 * <p>
 * The validator logs appropriate warning messages for validation failures.
 */
@Builder
public class TokenHeaderValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenHeaderValidator.class);

    @Getter
    @Singular("expectedIssuer")
    private final Set<String> expectedIssuer;

    @Getter
    @Builder.Default
    private final AlgorithmPreferences algorithmPreferences = new AlgorithmPreferences();

    /**
     * Constructs a TokenHeaderValidator with the specified expected issuers and algorithm preferences.
     *
     * @param expectedIssuer       the expected issuer(s) of the token
     * @param algorithmPreferences the algorithm preferences for validation
     * @throws IllegalArgumentException if no expected issuers are provided
     */
    @SuppressWarnings("java:S1144") // Suppressing this warning as the constructor is private and used only in the builder
    private TokenHeaderValidator(Set<String> expectedIssuer, AlgorithmPreferences algorithmPreferences) {
        // Validate configuration
        if (MoreCollections.isEmpty(expectedIssuer)) {
            throw new IllegalArgumentException("At least one expectedIssuer must be provided");
        }

        this.expectedIssuer = expectedIssuer;
        this.algorithmPreferences = algorithmPreferences != null ? algorithmPreferences : new AlgorithmPreferences();
    }

    /**
     * Validates a decoded JWT token's header.
     *
     * @param decodedJwt the decoded JWT token to validate
     * @return true if the token header is valid, false otherwise
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

        if (!algorithmPreferences.isSupported(algorithm.get())) {
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
    private boolean validateIssuer(DecodedJwt decodedJwt) {
        if (expectedIssuer.isEmpty()) {
            LOGGER.debug("No expected issuer is provided, skip validation");
            return true;
        }

        var issuer = decodedJwt.getIssuer();

        if (issuer.isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format("iss"));
            return false;
        }

        boolean correctIssuer = expectedIssuer.contains(issuer.get());
        if (!correctIssuer) {
            LOGGER.warn(JWTTokenLogMessages.WARN.ISSUER_MISMATCH.format(issuer.get(), expectedIssuer));
            return false;
        }

        LOGGER.debug("Successfully validated issuer: %s", issuer.get());
        return true;
    }
}
