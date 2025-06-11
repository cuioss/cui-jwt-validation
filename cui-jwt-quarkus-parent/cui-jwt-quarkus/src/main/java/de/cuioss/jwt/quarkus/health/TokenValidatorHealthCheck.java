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
package de.cuioss.jwt.quarkus.health;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

/**
 * Health check for TokenValidator functionality.
 * This class implements the SmallRye Health check interface to provide
 * liveness status for the JWT validation component.
 */
@ApplicationScoped
@Liveness // Marks this as a liveness check
public class TokenValidatorHealthCheck implements HealthCheck {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidatorHealthCheck.class);
    private static final String HEALTHCHECK_NAME = "jwt-validator";
    private static final String ERROR_NO_ISSUER_CONFIGS = "No issuer configurations found";
    private static final String ERROR = "error";
    private static final String STATUS_UP = "UP";
    private static final String STATUS_DOWN = "DOWN";

    private final TokenValidator tokenValidator;

    @Inject
    public TokenValidatorHealthCheck(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    @Override
    public HealthCheckResponse call() {
        var issuerConfigMap = tokenValidator.getIssuerConfigMap();
        if (issuerConfigMap == null || issuerConfigMap.isEmpty()) {
            return createErrorResponse(ERROR_NO_ISSUER_CONFIGS);
        }

        var responseBuilder = HealthCheckResponse.named(HEALTHCHECK_NAME).up();
        
        var results = issuerConfigMap.entrySet().stream()
            .map(entry -> ValidatorResult.fromIssuerConfig(entry.getKey(), entry.getValue()))
            .toList();
        
        // Add all validator data to response
        for (int i = 0; i < results.size(); i++) {
            results.get(i).addToResponse(responseBuilder, "issuer." + i + ".");
        }
        
        // Set overall health status - for liveness check, be more lenient
        // Only fail if all loaders are in ERROR state
        boolean allErrors = results.stream().allMatch(result -> result.status() == LoaderStatus.ERROR);
        responseBuilder.withData("checkedIssuers", results.size());
        
        if (allErrors && !results.isEmpty()) {
            responseBuilder.down();
        }
        
        return responseBuilder.build();
    }

    /**
     * Creates an error response with the given error message.
     *
     * @param errorMessage the error message
     * @return the health check response
     */
    private HealthCheckResponse createErrorResponse(String errorMessage) {
        return HealthCheckResponse.named(HEALTHCHECK_NAME)
                .down()
                .withData(ERROR, errorMessage)
                .build();
    }

    
    private record ValidatorResult(String issuer, String jwksType, LoaderStatus status) {
        
        /**
         * Creates a ValidatorResult from an issuer configuration.
         *
         * @param issuer the issuer name
         * @param issuerConfig the issuer configuration
         * @return the validator result
         */
        static ValidatorResult fromIssuerConfig(String issuer, IssuerConfig issuerConfig) {
            try {
                JwksLoader jwksLoader = issuerConfig.getJwksLoader();
                
                if (jwksLoader == null) {
                    return new ValidatorResult(issuer, JwksType.NONE.getValue(), LoaderStatus.ERROR);
                }
                
                LoaderStatus status = jwksLoader.getStatus();
                LOGGER.debug("JWKS loader status for issuer %s: %s", issuer, status);
                
                return new ValidatorResult(issuer, jwksLoader.getJwksType().getValue(), status);
            } catch (Exception e) {
                LOGGER.warn(e, "Error checking JWKS loader for issuer %s: %s", issuer, e.getMessage());
                return new ValidatorResult(issuer, JwksType.NONE.getValue(), LoaderStatus.ERROR);
            }
        }
        
        /**
         * Adds this validator's data to the health check response builder.
         *
         * @param responseBuilder the response builder
         * @param prefix the prefix for the data keys
         */
        void addToResponse(org.eclipse.microprofile.health.HealthCheckResponseBuilder responseBuilder, String prefix) {
            String statusStr = switch (status) {
                case OK -> STATUS_UP;
                case ERROR -> STATUS_DOWN;
                case UNDEFINED -> "UNDEFINED";
            };
            responseBuilder.withData(prefix + "issuer", issuer);
            responseBuilder.withData(prefix + "jwksType", jwksType);
            responseBuilder.withData(prefix + "status", statusStr);
        }
    }
}
