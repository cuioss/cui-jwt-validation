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
package de.cuioss.jwt.validation.jwks.http;

import de.cuioss.jwt.validation.JWTValidationLogMessages.DEBUG;
import de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;
import de.cuioss.jwt.validation.security.SecureSSLContextProvider;
import de.cuioss.jwt.validation.well_known.WellKnownHandler;
import de.cuioss.tools.http.HttpHandler;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Builder;
import lombok.NonNull;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Configuration parameters for {@link HttpJwksLoader}.
 * <p>
 * This class encapsulates all configuration options for the HttpJwksLoader,
 * including JWKS endpoint URL, refresh interval, SSL context, cache size,
 * and adaptive caching parameters. The JWKS endpoint URL can be configured
 * directly or discovered via a {@link WellKnownHandler}.
 * <p>
 * It provides validation for all parameters and default values where appropriate.
 * <p>
 * For more detailed information about the HTTP-based JWKS loading, see the
 * <a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/specification/technical-components.adoc#_jwksloader">Technical Components Specification</a>
 *
 * @author Oliver Wolff
 * @author Your Name (for well-known integration)
 * @since 1.0
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
     * Can be null if an invalid URL was provided.
     */
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
     * The HttpHandler used for HTTP requests.
     */
    @NonNull
    private final HttpHandler httpHandler;

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
     * @return the JWKS URI, or null if an invalid URL was provided
     */
    public URI getJwksUri() {
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
     * Gets the HttpHandler used for HTTP requests.
     *
     * @return the HttpHandler
     */
    public @NonNull HttpHandler getHttpHandler() {
        return httpHandler;
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
        private String jwksUrl; // Used if jwksUri is not set directly or via WellKnownHandler
        private URI jwksUri;     // Can be set directly, by jwksUrl(), or by well_known()
        private int refreshIntervalSeconds;
        private SSLContext sslContext;
        private SecureSSLContextProvider secureSSLContextProvider;
        private Integer maxCacheSize;
        private Integer adaptiveWindowSize;
        private Integer requestTimeoutSeconds;
        private Integer backgroundRefreshPercentage;
        private ScheduledExecutorService scheduledExecutorService;

        /**
         * Sets the JWKS URI directly.
         * <p>
         * Note: If this method is called, it will override any URI set by
         * {@link #jwksUrl(String)} or {@link #wellKnown(WellKnownHandler)}.
         * The last call among these methods determines the final JWKS URI.
         * </p>
         *
         * @param jwksUri the URI of the JWKS endpoint. Must not be null.
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder jwksUri(@NonNull URI jwksUri) {
            this.jwksUri = jwksUri;
            this.jwksUrl = null; // Clear jwksUrl to ensure jwksUri takes precedence
            return this;
        }

        /**
         * Sets the JWKS URL as a string, which will be converted to a URI.
         * <p>
         * Note: If this method is called, it will override any URI set by
         * {@link #jwksUri(URI)} or {@link #wellKnown(WellKnownHandler)}.
         * The last call among these methods determines the final JWKS URI.
         * </p>
         *
         * @param jwksUrl the URL string of the JWKS endpoint. Must not be null.
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder jwksUrl(@NonNull String jwksUrl) {
            this.jwksUrl = jwksUrl;
            this.jwksUri = null; // Clear jwksUri to allow jwksUrl to be processed
            return this;
        }

        /**
         * Configures the JWKS URI by extracting it from a {@link WellKnownHandler}.
         * <p>
         * This method will retrieve the {@code jwks_uri} from the provided
         * {@code WellKnownHandler}. If the handler does not contain a {@code jwks_uri},
         * an {@link IllegalArgumentException} will be thrown.
         * </p>
         * <p>
         * Note: If this method is called, it will override any URI set by
         * {@link #jwksUri(URI)} or {@link #jwksUrl(String)}.
         * The last call among these methods determines the final JWKS URI.
         * </p>
         *
         * @param wellKnownHandler The {@link WellKnownHandler} instance from which to
         *                         extract the JWKS URI. Must not be null.
         * @return this builder instance
         * @throws IllegalArgumentException if {@code wellKnownHandler} is null or does not
         *                                  contain a {@code jwks_uri}.
         */
        public HttpJwksLoaderConfigBuilder wellKnown(@NonNull WellKnownHandler wellKnownHandler) {
            HttpHandler extractedJwksHandler = wellKnownHandler.getJwksUri();
            this.jwksUri = extractedJwksHandler.getUri();
            this.jwksUrl = null; // Clear jwksUrl to ensure this URI takes precedence
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
            // If jwksUri is already set (by jwksUri() or well_known()), jwksUrl is ignored.
            // If jwksUri is null and jwksUrl is set, createJwksUri() will handle it.
            // If both are null, validateJwksSource() will throw.
            validateJwksSource();
            if (this.jwksUri == null && this.jwksUrl != null) {
                boolean uriCreated = createJwksUriFromUrlString();
                // If URI creation failed, we'll still create the config but with a null jwksUri
                // This allows the HttpJwksLoader to handle invalid URLs gracefully
                if (!uriCreated) {
                    LOGGER.warn(WARN.INVALID_JWKS_URI::format);
                }
            }
            validateParameters();

            SSLContext secureContext = createSecureSSLContext();

            int[] actualValues = applyDefaultValues();

            // Create HttpHandler for the JWKS URI
            HttpHandler jwksHttpHandler = null;
            if (jwksUri != null) {
                jwksHttpHandler = HttpHandler.builder()
                        .uri(jwksUri)
                        .sslContext(secureContext)
                        .requestTimeoutSeconds(actualValues[2]) // requestTimeoutSeconds
                        .build();
            } else {
                // If jwksUri is null, create a dummy HttpHandler that will fail gracefully
                LOGGER.warn(WARN.INVALID_JWKS_URI::format);
                jwksHttpHandler = HttpHandler.builder()
                        .uri("https://invalid.uri")
                        .sslContext(secureContext)
                        .requestTimeoutSeconds(actualValues[2]) // requestTimeoutSeconds
                        .build();
            }

            return new HttpJwksLoaderConfig(
                    jwksUri,
                    refreshIntervalSeconds,
                    secureContext,
                    jwksHttpHandler,
                    actualValues[0], // maxCacheSize
                    actualValues[1], // adaptiveWindowSize
                    actualValues[2], // requestTimeoutSeconds
                    actualValues[3], // backgroundRefreshPercentage
                    scheduledExecutorService);
        }

        /**
         * Validates that a source for the JWKS URI (either direct URI, URL string, or WellKnownHandler) is provided.
         *
         * @throws IllegalArgumentException if no JWKS source is configured.
         */
        private void validateJwksSource() {
            if (jwksUri == null && jwksUrl == null) {
                throw new IllegalArgumentException("JWKS URI must be configured. Use jwksUri(), jwksUrl(), or well_known().");
            }
        }

        /**
         * Creates a URI from the JWKS URL string if jwksUri is not already set.
         * This is called if jwksUrl() was used and jwksUri() or well_known() were not.
         * 
         * @return true if the URI was created successfully, false if the URL was invalid
         */
        private boolean createJwksUriFromUrlString() {
            if (jwksUri == null && jwksUrl != null) { // Should only be called if jwksUrl is the source
                try {
                    String urlToUse = jwksUrl;
                    if (!urlToUse.matches("^[a-zA-Z][a-zA-Z0-9+.-]*:.*")) {
                        // Basic check if scheme is missing, prepend https as a sensible default for JWKS
                        LOGGER.debug(DEBUG.JWKS_URL_MISSING_SCHEME.format(jwksUrl));
                        urlToUse = "https://" + urlToUse;
                    }
                    jwksUri = URI.create(urlToUse);
                    LOGGER.debug(DEBUG.JWKS_URI_CREATED.format(jwksUri, jwksUrl));
                    return true;
                } catch (IllegalArgumentException e) {
                    // Log the error but don't throw, to allow graceful handling of invalid URLs
                    LOGGER.warn(e, WARN.INVALID_JWKS_URL_STRING.format(jwksUrl));
                    // Set jwksUri to null to indicate an invalid URL
                    jwksUri = null;
                    return false;
                }
            }
            return jwksUri != null;
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
