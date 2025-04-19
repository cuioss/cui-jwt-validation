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
package de.cuioss.jwt.token.jwks.http;

import de.cuioss.jwt.token.security.SecureSSLContextProvider;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Builder;
import lombok.NonNull;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Configuration parameters for {@link HttpJwksLoader}.
 * <p>
 * This class encapsulates all configuration options for the HttpJwksLoader,
 * including JWKS endpoint URL, refresh interval, SSL context, cache size,
 * and adaptive caching parameters.
 * <p>
 * It provides validation for all parameters and default values where appropriate.
 *
 * @author Oliver Wolff
 */
@Builder
public class HttpJwksLoaderConfig {

    private static final CuiLogger LOGGER = new CuiLogger(HttpJwksLoaderConfig.class);
    private static final int DEFAULT_REQUEST_TIMEOUT_SECONDS = 10;
    private static final int DEFAULT_MAX_CACHE_SIZE = 100;
    private static final int DEFAULT_BACKGROUND_REFRESH_PERCENTAGE = 80;
    private static final int DEFAULT_ADAPTIVE_WINDOW_SIZE = 10;

    /**
     * The URI of the JWKS endpoint.
     */
    @NonNull
    private final URI jwksUri;

    /**
     * The interval in seconds at which to refresh the keys.
     * If set to 0, no time-based caching will be used.
     */
    private final int refreshIntervalSeconds;

    /**
     * The SSLContext for secure connections.
     */
    @NonNull
    private final SSLContext sslContext;

    /**
     * The maximum number of entries in the cache.
     * This is useful in multi-issuer environments to prevent memory issues.
     */
    private final int maxCacheSize;

    /**
     * The number of accesses to consider for adaptive caching.
     * This controls how many accesses are considered when adjusting cache expiration.
     */
    private final int adaptiveWindowSize;

    /**
     * The timeout in seconds for HTTP requests.
     */
    private final int requestTimeoutSeconds;

    /**
     * The percentage of the refresh interval at which to perform background refresh.
     * For example, if refreshIntervalSeconds is 60 and backgroundRefreshPercentage is 80,
     * background refresh will occur at 48 seconds (80% of 60).
     */
    private final int backgroundRefreshPercentage;

    /**
     * The ScheduledExecutorService for background refresh tasks.
     * If null, a new one will be created.
     */
    private final ScheduledExecutorService scheduledExecutorService;

    /**
     * Gets the URI of the JWKS endpoint.
     *
     * @return the JWKS URI
     */
    public @NonNull URI getJwksUri() {
        return jwksUri;
    }

    /**
     * Gets the refresh interval in seconds.
     *
     * @return the refresh interval in seconds
     */
    public int getRefreshIntervalSeconds() {
        return refreshIntervalSeconds;
    }

    /**
     * Gets the SSLContext for secure connections.
     *
     * @return the SSLContext
     */
    public @NonNull SSLContext getSslContext() {
        return sslContext;
    }

    /**
     * Gets the maximum number of entries in the cache.
     *
     * @return the maximum cache size
     */
    public int getMaxCacheSize() {
        return maxCacheSize;
    }

    /**
     * Gets the number of accesses to consider for adaptive caching.
     *
     * @return the adaptive window size
     */
    public int getAdaptiveWindowSize() {
        return adaptiveWindowSize;
    }

    /**
     * Gets the timeout in seconds for HTTP requests.
     *
     * @return the request timeout in seconds
     */
    public int getRequestTimeoutSeconds() {
        return requestTimeoutSeconds;
    }

    /**
     * Gets the percentage of the refresh interval at which to perform background refresh.
     *
     * @return the background refresh percentage
     */
    public int getBackgroundRefreshPercentage() {
        return backgroundRefreshPercentage;
    }

    /**
     * Gets the ScheduledExecutorService for background refresh tasks.
     * If the ScheduledExecutorService is null and the refresh interval is positive,
     * a new one will be created.
     *
     * @return the ScheduledExecutorService, or a new one if null
     */
    public ScheduledExecutorService getScheduledExecutorService() {
        if (scheduledExecutorService == null && refreshIntervalSeconds > 0) {
            return Executors.newScheduledThreadPool(1);
        }
        return scheduledExecutorService;
    }

    /**
     * Builder for creating HttpJwksLoaderConfig instances with validation.
     */
    public static class HttpJwksLoaderConfigBuilder {
        private String jwksUrl;
        private URI jwksUri;
        private int refreshIntervalSeconds;
        private SSLContext sslContext;
        private SecureSSLContextProvider secureSSLContextProvider;
        private Integer maxCacheSize;
        private Integer adaptiveWindowSize;
        private Integer requestTimeoutSeconds;
        private Integer backgroundRefreshPercentage;
        private ScheduledExecutorService scheduledExecutorService;

        /**
         * Sets the JWKS URL.
         *
         * @param jwksUrl the URL of the JWKS endpoint
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder jwksUrl(@NonNull String jwksUrl) {
            this.jwksUrl = jwksUrl;
            return this;
        }

        /**
         * Sets the TLS versions configuration.
         *
         * @param secureSSLContextProvider the TLS versions configuration to use
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder tlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            this.secureSSLContextProvider = secureSSLContextProvider;
            return this;
        }

        /**
         * Sets the ScheduledExecutorService for background refresh tasks.
         *
         * @param scheduledExecutorService the ScheduledExecutorService to use
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder scheduledExecutorService(ScheduledExecutorService scheduledExecutorService) {
            this.scheduledExecutorService = scheduledExecutorService;
            return this;
        }

        /**
         * Builds a new HttpJwksLoaderConfig instance with the configured parameters.
         * Validates all parameters and applies default values where appropriate.
         *
         * @return a new HttpJwksLoaderConfig instance
         * @throws IllegalArgumentException if any parameter is invalid
         */
        public HttpJwksLoaderConfig build() {
            validateJwksUrl();
            createJwksUri();
            validateParameters();

            SSLContext secureContext = createSecureSSLContext();

            int[] actualValues = applyDefaultValues();

            return new HttpJwksLoaderConfig(
                    jwksUri,
                    refreshIntervalSeconds,
                    secureContext,
                    actualValues[0], // maxCacheSize
                    actualValues[1], // adaptiveWindowSize
                    actualValues[2], // requestTimeoutSeconds
                    actualValues[3], // backgroundRefreshPercentage
                    scheduledExecutorService);
        }

        /**
         * Validates that the JWKS URL is provided.
         * 
         * @throws IllegalArgumentException if JWKS URL is not provided
         */
        private void validateJwksUrl() {
            if (jwksUrl == null && jwksUri == null) {
                throw new IllegalArgumentException("JWKS URL must not be null or empty");
            }
        }

        /**
         * Creates a URI from the JWKS URL if not already set.
         */
        private void createJwksUri() {
            if (jwksUri == null) {
                try {
                    // Add scheme if missing to avoid URI with undefined scheme error
                    String urlToUse = jwksUrl;
                    if (!urlToUse.contains("://")) {
                        urlToUse = "http://" + urlToUse;
                    }
                    jwksUri = URI.create(urlToUse);
                } catch (IllegalArgumentException e) {
                    // Create a dummy URI for invalid URLs to allow graceful handling
                    jwksUri = URI.create("http://invalid-url");
                    LOGGER.warn("Invalid JWKS URL: %s, using dummy URI", jwksUrl);
                }
            }
        }

        /**
         * Validates all parameters.
         * 
         * @throws IllegalArgumentException if any parameter is invalid
         */
        private void validateParameters() {
            validateRefreshInterval();
            validateMaxCacheSize();
            validateAdaptiveWindowSize();
            validateRequestTimeout();
            validateBackgroundRefreshPercentage();
        }

        /**
         * Validates the refresh interval.
         * 
         * @throws IllegalArgumentException if refresh interval is negative
         */
        private void validateRefreshInterval() {
            if (refreshIntervalSeconds < 0) {
                throw new IllegalArgumentException("Refresh interval must not be negative");
            }
        }

        /**
         * Validates the max cache size.
         * 
         * @throws IllegalArgumentException if max cache size is not positive
         */
        private void validateMaxCacheSize() {
            if (maxCacheSize != null && maxCacheSize <= 0) {
                throw new IllegalArgumentException("Max cache size must be positive");
            }
        }

        /**
         * Validates the adaptive window size.
         * 
         * @throws IllegalArgumentException if adaptive window size is not positive
         */
        private void validateAdaptiveWindowSize() {
            if (adaptiveWindowSize != null && adaptiveWindowSize <= 0) {
                throw new IllegalArgumentException("Adaptive window size must be positive");
            }
        }

        /**
         * Validates the request timeout.
         * 
         * @throws IllegalArgumentException if request timeout is not positive
         */
        private void validateRequestTimeout() {
            if (requestTimeoutSeconds != null && requestTimeoutSeconds <= 0) {
                throw new IllegalArgumentException("Request timeout must be positive");
            }
        }

        /**
         * Validates the background refresh percentage.
         * 
         * @throws IllegalArgumentException if background refresh percentage is not between 1 and 100
         */
        private void validateBackgroundRefreshPercentage() {
            if (backgroundRefreshPercentage != null && (backgroundRefreshPercentage <= 0 || backgroundRefreshPercentage > 100)) {
                throw new IllegalArgumentException("Background refresh percentage must be between 1 and 100");
            }
        }

        /**
         * Creates a secure SSL context.
         * 
         * @return a secure SSL context
         */
        private SSLContext createSecureSSLContext() {
            // Create default SecureSSLContextProvider instance if none is provided
            SecureSSLContextProvider actualSecureSSLContextProvider = secureSSLContextProvider != null ?
                    secureSSLContextProvider : new SecureSSLContextProvider();

            // Get or create a secure SSLContext using the SecureSSLContextProvider configuration
            return actualSecureSSLContextProvider.getOrCreateSecureSSLContext(sslContext);
        }

        /**
         * Applies default values to parameters if not specified.
         * 
         * @return an array of actual values in the order: maxCacheSize, adaptiveWindowSize, requestTimeoutSeconds, backgroundRefreshPercentage
         */
        private int[] applyDefaultValues() {
            int actualMaxCacheSize = maxCacheSize != null ? maxCacheSize : DEFAULT_MAX_CACHE_SIZE;
            int actualAdaptiveWindowSize = adaptiveWindowSize != null ? adaptiveWindowSize : DEFAULT_ADAPTIVE_WINDOW_SIZE;
            int actualRequestTimeoutSeconds = requestTimeoutSeconds != null ?
                    requestTimeoutSeconds : DEFAULT_REQUEST_TIMEOUT_SECONDS;
            int actualBackgroundRefreshPercentage = backgroundRefreshPercentage != null ?
                    backgroundRefreshPercentage : DEFAULT_BACKGROUND_REFRESH_PERCENTAGE;

            return new int[]{
                    actualMaxCacheSize,
                    actualAdaptiveWindowSize,
                    actualRequestTimeoutSeconds,
                    actualBackgroundRefreshPercentage
            };
        }
    }
}
