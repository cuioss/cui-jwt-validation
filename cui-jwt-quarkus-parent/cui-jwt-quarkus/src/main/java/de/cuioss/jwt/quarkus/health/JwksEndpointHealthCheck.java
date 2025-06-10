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

import de.cuioss.jwt.quarkus.producer.TokenValidatorProducer;
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
import org.eclipse.microprofile.health.Readiness;

import java.util.List;

/**
 * Health check for JWKS endpoint connectivity.
 * This class implements the SmallRye Health check interface to provide
 * readiness status for JWT validation JWKS endpoints.
 */
@ApplicationScoped
@Readiness // Marks this as a readiness check
public class JwksEndpointHealthCheck implements HealthCheck {

    private static final CuiLogger LOGGER = new CuiLogger(JwksEndpointHealthCheck.class);
    private static final String HEALTHCHECK_NAME = "jwks-endpoints";
    private static final String ERROR_NO_ISSUER_CONFIGS = "No issuer configurations found";
    private static final String ERROR_NO_HTTP_JWKS = "No HTTP JWKS endpoints configured";
    private static final String ERROR = "error";
    private static final String STATUS_UP = "UP";
    private static final String STATUS_DOWN = "DOWN";

    private final TokenValidatorProducer tokenValidatorProducer;

    @Inject
    public JwksEndpointHealthCheck(TokenValidatorProducer tokenValidatorProducer) {
        this.tokenValidatorProducer = tokenValidatorProducer;
    }

    @Override
    public HealthCheckResponse call() {
        try {
            TokenValidator tokenValidator = tokenValidatorProducer.getTokenValidator();
            if (tokenValidator == null) {
                return createErrorResponse("TokenValidator not available");
            }
            
            var issuerConfigMap = tokenValidator.getIssuerConfigMap();
            if (issuerConfigMap == null || issuerConfigMap.isEmpty()) {
                return createErrorResponse(ERROR_NO_ISSUER_CONFIGS);
            }

            return checkJwksEndpoints(issuerConfigMap.values().stream().toList());
        } catch (Exception e) {
            LOGGER.warn(e, "Error checking JWKS endpoints: %s", e.getMessage());
            return createErrorResponse(e.getMessage());
        }
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

    /**
     * Checks all JWKS endpoints in the given issuer configurations.
     *
     * @param issuerConfigs the issuer configurations
     * @return the health check response
     */
    private HealthCheckResponse checkJwksEndpoints(List<IssuerConfig> issuerConfigs) {
        boolean allEndpointsUp = true;
        int checkedEndpoints = 0;
        int i = 0;

        // Create a response builder
        var responseBuilder = HealthCheckResponse.named(HEALTHCHECK_NAME).up();

        for (IssuerConfig issuerConfig : issuerConfigs) {
            String jwksType = determineJwksType(issuerConfig);

            // Only check HTTP JWKS endpoints
            if (!JwksType.HTTP.getValue().equals(jwksType)) {
                i++;
                continue;
            }

            checkedEndpoints++;
            String prefix = "issuer." + i + ".";
            boolean up = checkJwksEndpointConnectivity(issuerConfig);

            addEndpointData(responseBuilder, prefix, issuerConfig.getIssuer(), jwksType, up);

            if (!up) {
                allEndpointsUp = false;
            }
            i++;
        }

        responseBuilder.withData("checkedEndpoints", checkedEndpoints);
        return finalizeHealthCheckResponse(responseBuilder, checkedEndpoints, allEndpointsUp);
    }

    /**
     * Determines the JWKS type for the given issuer configuration.
     *
     * @param issuerConfig the issuer configuration
     * @return the JWKS type
     */
    private String determineJwksType(IssuerConfig issuerConfig) {
        if (issuerConfig.getHttpJwksLoaderConfig() != null) {
            return JwksType.HTTP.getValue();
        } else if (issuerConfig.getJwksFilePath() != null) {
            return JwksType.FILE.getValue();
        } else if (issuerConfig.getJwksContent() != null) {
            return JwksType.MEMORY.getValue();
        } else {
            return JwksType.NONE.getValue();
        }
    }

    /**
     * Adds endpoint data to the health check response builder.
     *
     * @param builder the health check response builder
     * @param prefix the prefix for the data
     * @param issuerUrl the issuer URL
     * @param jwksType the JWKS type
     * @param up whether the endpoint is up
     */
    private void addEndpointData(org.eclipse.microprofile.health.HealthCheckResponseBuilder builder, String prefix,
                                String issuerUrl, String jwksType, boolean up) {
        builder.withData(prefix + "url", issuerUrl);
        builder.withData(prefix + "jwksType", jwksType);
        builder.withData(prefix + "status", up ? STATUS_UP : STATUS_DOWN);
    }

    /**
     * Finalizes the health check response based on the checked endpoints and their status.
     *
     * @param builder the health check response builder
     * @param checkedEndpoints the number of checked endpoints
     * @param allEndpointsUp whether all endpoints are up
     * @return the health check response
     */
    private HealthCheckResponse finalizeHealthCheckResponse(org.eclipse.microprofile.health.HealthCheckResponseBuilder builder,
                                                         int checkedEndpoints,
                                                         boolean allEndpointsUp) {
        if (checkedEndpoints == 0) {
            builder.down().withData(ERROR, ERROR_NO_HTTP_JWKS);
        } else if (!allEndpointsUp) {
            builder.down();
        }
        return builder.build();
    }

    /**
     * Checks the connectivity to a JWKS endpoint by examining the loader status.
     *
     * @param issuerConfig the issuer configuration
     * @return true if the endpoint is accessible (LoaderStatus.OK), false otherwise
     */
    private boolean checkJwksEndpointConnectivity(IssuerConfig issuerConfig) {
        try {
            JwksLoader jwksLoader = issuerConfig.getJwksLoader();
            if (jwksLoader == null) {
                return false;
            }
            
            LoaderStatus status = jwksLoader.getStatus();
            LOGGER.debug("JWKS loader status for issuer %s: %s", issuerConfig.getIssuer(), status);
            
            return status == LoaderStatus.OK;
        } catch (Exception e) {
            LOGGER.debug(e, "Error checking JWKS endpoint for issuer %s: %s",
                    issuerConfig.getIssuer(), e.getMessage());
            return false;
        }
    }
}
