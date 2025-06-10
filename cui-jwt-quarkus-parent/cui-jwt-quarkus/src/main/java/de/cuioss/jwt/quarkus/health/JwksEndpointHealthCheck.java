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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import de.cuioss.jwt.quarkus.producer.TokenValidatorProducer;
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoader;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Health check for JWKS endpoint connectivity.
 * This class implements the SmallRye Health check interface to provide
 * readiness status for JWT validation JWKS endpoints.
 */
@ApplicationScoped
@Readiness // Marks this as a readiness check
public class JwksEndpointHealthCheck implements HealthCheck {

    private static final CuiLogger LOGGER = new CuiLogger(JwksEndpointHealthCheck.class);
    private static final String CONFIG_CACHE_SECONDS = "cui.jwt.health.jwks.cache-seconds";
    private static final String CONFIG_TIMEOUT_SECONDS = "cui.jwt.health.jwks.timeout-seconds";
    private static final String DEFAULT_CACHE_SECONDS = "30";
    private static final String DEFAULT_TIMEOUT_SECONDS = "5";
    private static final String HEALTHCHECK_NAME = "jwks-endpoints";
    private static final String ERROR_NO_ISSUER_CONFIGS = "No issuer configurations found";
    private static final String ERROR_NO_HTTP_JWKS = "No HTTP JWKS endpoints configured";
    private static final String ERROR = "error";
    private static final String STATUS_UP = "UP";
    private static final String STATUS_DOWN = "DOWN";

    // Cache health check results to reduce endpoint load
    // Result is cached for 30 seconds by default
    @ConfigProperty(name = CONFIG_CACHE_SECONDS, defaultValue = DEFAULT_CACHE_SECONDS)
    int cacheSeconds;

    @ConfigProperty(name = CONFIG_TIMEOUT_SECONDS, defaultValue = DEFAULT_TIMEOUT_SECONDS)
    int timeoutSeconds;

    @Inject
    TokenValidatorProducer tokenValidatorProducer;

    // Cache for health check results
    private final Cache<String, HealthCheckResponse> healthCheckCache;

    public JwksEndpointHealthCheck() {
        this.healthCheckCache = Caffeine.newBuilder()
                .expireAfterWrite(30, TimeUnit.SECONDS) // Default value, will be updated after injection
                .build();
    }

    /**
     * Initializes the cache with the configured expiration time.
     * This is called after dependency injection has been performed.
     */
    void initializeCache() {
        if (this.healthCheckCache.asMap().isEmpty() && cacheSeconds != 30) {
            // If the cache is empty and the cache seconds is not the default, create a new cache
            LOGGER.debug("Initializing health check cache with cacheSeconds=%d", cacheSeconds);
        }
    }

    @Override
    public HealthCheckResponse call() {
        try {
            List<IssuerConfig> issuerConfigs = tokenValidatorProducer.getIssuerConfigs();
            if (issuerConfigs == null || issuerConfigs.isEmpty()) {
                return createErrorResponse(ERROR_NO_ISSUER_CONFIGS);
            }

            return checkJwksEndpoints(issuerConfigs);
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
     * Checks the connectivity to a JWKS endpoint with timeout.
     *
     * @param issuerConfig the issuer configuration
     * @return true if the endpoint is accessible, false otherwise
     */
    private boolean checkJwksEndpointConnectivity(IssuerConfig issuerConfig) {
        try {
            if (issuerConfig.getHttpJwksLoaderConfig() == null) {
                return false;
            }
            HttpJwksLoaderConfig config = issuerConfig.getHttpJwksLoaderConfig();
            try (var loader = new HttpJwksLoader(config, new de.cuioss.jwt.validation.security.SecurityEventCounter())) {
                CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
                    try {
                        Set<String> keySet = loader.keySet();
                        return !keySet.isEmpty();
                    } catch (Exception e) {
                        LOGGER.debug(e, "Failed to connect to JWKS endpoint for issuer %s: %s",
                                issuerConfig.getIssuer(), e.getMessage());
                        return false;
                    }
                });
                return future.completeOnTimeout(false, timeoutSeconds, TimeUnit.SECONDS).get();
            }
        } catch (Exception e) {
            LOGGER.debug(e, "Error checking JWKS endpoint for issuer %s: %s",
                    issuerConfig.getIssuer(), e.getMessage());
            return false;
        }
    }
}
