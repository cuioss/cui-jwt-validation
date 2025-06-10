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

    // Cache health check results to reduce endpoint load
    // Result is cached for 30 seconds by default
    @ConfigProperty(name = "cui.jwt.health.jwks.cache-seconds", defaultValue = "30")
    int cacheSeconds;

    @ConfigProperty(name = "cui.jwt.health.jwks.timeout-seconds", defaultValue = "5")
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
        var builder = HealthCheckResponse.named("jwks-endpoints").up();
        try {
            List<IssuerConfig> issuerConfigs = tokenValidatorProducer.getIssuerConfigs();
            if (issuerConfigs == null || issuerConfigs.isEmpty()) {
                return HealthCheckResponse.named("jwks-endpoints")
                        .down()
                        .withData("error", "No issuer configurations found")
                        .build();
            }
            boolean allEndpointsUp = true;
            int checkedEndpoints = 0;
            int i = 0;
            for (IssuerConfig issuerConfig : issuerConfigs) {
                String issuerUrl = issuerConfig.getIssuer();
                String jwksType = null;
                if (issuerConfig.getHttpJwksLoaderConfig() != null) {
                    jwksType = "http";
                } else if (issuerConfig.getJwksFilePath() != null) {
                    jwksType = "file";
                } else if (issuerConfig.getJwksContent() != null) {
                    jwksType = "memory";
                } else {
                    jwksType = "none";
                }
                // Only check HTTP JWKS endpoints
                if (!"http".equals(jwksType)) {
                    i++;
                    continue;
                }
                checkedEndpoints++;
                String prefix = "issuer." + i + ".";
                boolean up = checkJwksEndpointConnectivity(issuerConfig);
                builder.withData(prefix + "url", issuerUrl);
                builder.withData(prefix + "jwksType", jwksType);
                builder.withData(prefix + "status", up ? "UP" : "DOWN");
                if (!up) {
                    allEndpointsUp = false;
                }
                i++;
            }
            builder.withData("checkedEndpoints", checkedEndpoints);
            if (checkedEndpoints == 0) {
                builder.down().withData("error", "No HTTP JWKS endpoints configured");
            } else if (!allEndpointsUp) {
                builder.down();
            }
            return builder.build();
        } catch (Exception e) {
            LOGGER.warn(e, "Error checking JWKS endpoints: %s", e.getMessage());
            return HealthCheckResponse.named("jwks-endpoints")
                    .down()
                    .withData("error", e.getMessage())
                    .build();
        }
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
