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
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;

import java.util.Map;
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
    private static final String DEFAULT_CACHE_SECONDS = "30";
    private static final String HEALTHCHECK_NAME = "jwks-endpoints";
    private static final String ERROR_NO_ISSUER_CONFIGS = "No issuer configurations found";
    private static final String ERROR = "error";
    private static final String STATUS_UP = "UP";
    private static final String STATUS_DOWN = "DOWN";

    private final TokenValidator tokenValidator;
    private final Cache<String, HealthCheckResponse> healthCheckCache;

    @Inject
    public JwksEndpointHealthCheck(TokenValidator tokenValidator,
                                   @ConfigProperty(name = CONFIG_CACHE_SECONDS, defaultValue = DEFAULT_CACHE_SECONDS) int cacheSeconds) {
        this.tokenValidator = tokenValidator;
        this.healthCheckCache = Caffeine.newBuilder()
                .expireAfterWrite(cacheSeconds, TimeUnit.SECONDS)
                .build();
    }

    @Override
    public HealthCheckResponse call() {
        try {
            // Use cache to prevent excessive network calls
            return healthCheckCache.get(HEALTHCHECK_NAME, k -> performHealthCheck());
        } catch (Exception e) {
            LOGGER.warn(e, "Error checking JWKS endpoints: %s", e.getMessage());
            return createErrorResponse(e.getMessage());
        }
    }

    /**
     * Performs the actual health check without caching.
     *
     * @return the health check response
     */
    private HealthCheckResponse performHealthCheck() {
        var issuerConfigMap = tokenValidator.getIssuerConfigMap();
        if (issuerConfigMap == null || issuerConfigMap.isEmpty()) {
            return createErrorResponse(ERROR_NO_ISSUER_CONFIGS);
        }

        return checkJwksEndpoints(issuerConfigMap);
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
     * Checks all JWKS endpoints in the given issuer configuration map.
     *
     * @param issuerConfigMap the issuer configuration map
     * @return the health check response
     */
    private HealthCheckResponse checkJwksEndpoints(Map<String, IssuerConfig> issuerConfigMap) {
        var responseBuilder = HealthCheckResponse.named(HEALTHCHECK_NAME).up();
        
        var results = issuerConfigMap.entrySet().stream()
            .map(entry -> {
                String issuer = entry.getKey();
                JwksLoader jwksLoader = entry.getValue().getJwksLoader();
                
                if (jwksLoader == null) {
                    return new EndpointResult(issuer, JwksType.NONE.getValue(), LoaderStatus.ERROR);
                }
                
                LoaderStatus status = jwksLoader.getStatus();
                LOGGER.debug("JWKS loader status for issuer %s: %s", issuer, status);
                
                return new EndpointResult(issuer, jwksLoader.getJwksType().getValue(), status);
            })
            .toList();
        
        // Add all endpoint data to response
        for (int i = 0; i < results.size(); i++) {
            var result = results.get(i);
            String prefix = "issuer." + i + ".";
            boolean up = result.status == LoaderStatus.OK;
            
            responseBuilder.withData(prefix + "url", result.issuer);
            responseBuilder.withData(prefix + "jwksType", result.jwksType);
            responseBuilder.withData(prefix + "status", up ? STATUS_UP : STATUS_DOWN);
        }
        
        // Set overall health status
        boolean allUp = results.stream().allMatch(r -> r.status == LoaderStatus.OK);
        responseBuilder.withData("checkedEndpoints", results.size());
        
        if (results.isEmpty()) {
            responseBuilder.down().withData(ERROR, ERROR_NO_ISSUER_CONFIGS);
        } else if (!allUp) {
            responseBuilder.down();
        }
        
        return responseBuilder.build();
    }
    
    private record EndpointResult(String issuer, String jwksType, LoaderStatus status) {}
}
