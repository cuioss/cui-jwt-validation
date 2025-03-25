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
package de.cuioss.jwt.token.jwks;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import de.cuioss.jwt.token.security.SecureSSLContextProvider;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static de.cuioss.jwt.token.JWTTokenLogMessages.DEBUG;
import static de.cuioss.jwt.token.JWTTokenLogMessages.WARN;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from an HTTP endpoint.
 * Uses Caffeine cache for caching keys.
 * <p>
 * This implementation includes several performance and reliability enhancements:
 * <ul>
 *   <li>HTTP 304 "Not Modified" handling: Uses the ETag header to avoid unnecessary downloads</li>
 *   <li>Content-based caching: Only creates new key loaders when content actually changes</li>
 *   <li>Fallback mechanism: Uses the last valid result if a new request fails</li>
 * </ul>
 * <p>
 * Implements requirement: {@code CUI-JWT-8.3: Secure Communication}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 */
@ToString(exclude = {"jwksCache"})
@EqualsAndHashCode(exclude = {"jwksCache"})
public class HttpJwksLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(HttpJwksLoader.class);
    private static final int DEFAULT_REQUEST_TIMEOUT_SECONDS = 10;
    private static final String EMPTY_JWKS = "{}";
    private static final String CACHE_KEY = "jwks";
    private static final int HTTP_OK = 200;

    private final URI jwksUri;
    private final int refreshIntervalSeconds;
    private final LoadingCache<String, JWKSKeyLoader> jwksCache;
    private final HttpClient httpClient;
    private JWKSKeyLoader lastValidResult;

    /**
     * Creates a new HttpJwksLoader with the specified parameters.
     *
     * @param jwksUrl                the URL of the JWKS endpoint
     * @param refreshIntervalSeconds the interval in seconds at which to refresh the keys
     * @param sslContext             the SSLContext for secure connections
     */
    private HttpJwksLoader(@NonNull String jwksUrl, int refreshIntervalSeconds, @NonNull SSLContext sslContext) {
        this.jwksUri = validateAndCreateUri(jwksUrl);
        this.refreshIntervalSeconds = refreshIntervalSeconds;
        this.httpClient = createHttpClient(sslContext);
        this.lastValidResult = null;

        // Configure cache based on refresh interval
        Caffeine<Object, Object> builder = Caffeine.newBuilder();

        // If refreshIntervalSeconds is 0, don't set expiration or refresh policies
        if (refreshIntervalSeconds > 0) {
            builder.expireAfterWrite(Duration.ofSeconds(refreshIntervalSeconds))
                    .refreshAfterWrite(Duration.ofSeconds(refreshIntervalSeconds));
        }

        this.jwksCache = builder.build(this::loadJwksKeyLoader);

        // Initial JWKS content fetch to populate cache
        jwksCache.get(CACHE_KEY);

        LOGGER.debug(DEBUG.INITIALIZED_JWKS_LOADER.format(
                jwksUri.toString(), refreshIntervalSeconds));
    }

    /**
     * Builder for creating HttpJwksLoader instances.
     */
    public static class Builder {
        private String jwksUrl;
        private int refreshIntervalSeconds;
        private SSLContext sslContext;
        private SecureSSLContextProvider secureSSLContextProvider;

        /**
         * Sets the JWKS URL.
         *
         * @param jwksUrl the URL of the JWKS endpoint
         * @return this builder instance
         */
        public Builder withJwksUrl(@NonNull String jwksUrl) {
            this.jwksUrl = jwksUrl;
            return this;
        }

        /**
         * Sets the refresh interval in seconds.
         *
         * @param refreshIntervalSeconds the interval in seconds at which to refresh the keys
         * @return this builder instance
         */
        public Builder withRefreshInterval(int refreshIntervalSeconds) {
            this.refreshIntervalSeconds = refreshIntervalSeconds;
            return this;
        }

        /**
         * Sets the SSL context.
         *
         * @param sslContext the SSL context to use
         * @return this builder instance
         */
        public Builder withSslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        /**
         * Sets the TLS versions configuration.
         *
         * @param secureSSLContextProvider the TLS versions configuration to use
         * @return this builder instance
         */
        public Builder withTlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            this.secureSSLContextProvider = secureSSLContextProvider;
            return this;
        }

        /**
         * Builds a new HttpJwksLoader instance with the configured parameters.
         * If refreshIntervalSeconds is 0, no time-based caching will be used.
         * If secureSSLContextProvider is null, a default instance will be created.
         * The method creates the correct SSLContext using the TLSVersions configuration.
         *
         * @return a new HttpJwksLoader instance
         * @throws IllegalArgumentException if jwksUrl is null or empty, or if refreshIntervalSeconds is negative
         */
        public HttpJwksLoader build() {
            if (jwksUrl == null || jwksUrl.isEmpty()) {
                throw new IllegalArgumentException("JWKS URL must not be null or empty");
            }
            if (refreshIntervalSeconds < 0) {
                throw new IllegalArgumentException("Refresh interval must not be negative");
            }

            // Create default SecureSSLContextProvider instance if none is provided
            SecureSSLContextProvider actualSecureSSLContextProvider = secureSSLContextProvider != null ? secureSSLContextProvider : new SecureSSLContextProvider();

            // Get or create a secure SSLContext using the SecureSSLContextProvider configuration
            SSLContext secureContext = actualSecureSSLContextProvider.getOrCreateSecureSSLContext(sslContext);

            return new HttpJwksLoader(jwksUrl, refreshIntervalSeconds, secureContext);
        }
    }

    /**
     * Creates a new builder for HttpJwksLoader.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Validates the JWKS URL and creates a URI.
     *
     * @param jwksUrl the URL of the JWKS endpoint
     * @return the validated URI
     * @throws IllegalArgumentException if the URL is invalid
     */
    private URI validateAndCreateUri(String jwksUrl) {
        try {
            return URI.create(jwksUrl);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid JWKS URL: " + jwksUrl, e);
        }
    }


    /**
     * Creates an HTTP client with the specified SSL context.
     * The SSL context is guaranteed to be non-null and secure as it's created in the build method.
     *
     * @param sslContext the SSL context to use
     * @return the HTTP client
     */
    private HttpClient createHttpClient(@NonNull SSLContext sslContext) {
        HttpClient.Builder httpClientBuilder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(DEFAULT_REQUEST_TIMEOUT_SECONDS))
                .sslContext(sslContext);

        LOGGER.debug(DEBUG.USING_SSL_CONTEXT.format(sslContext.getProtocol()));

        return httpClientBuilder.build();
    }

    /**
     * Resolves a JWKSKeyLoader for the current JWKS content.
     * This method gets the current JWKSKeyLoader from the cache, which will trigger a refresh if needed.
     *
     * @return a JWKSKeyLoader instance with the current JWKS content
     */
    public JWKSKeyLoader resolve() {
        LOGGER.debug(DEBUG.RESOLVING_KEY_LOADER.format(jwksUri.toString()));

        try {
            // If refreshIntervalSeconds is 0, bypass the cache and load directly
            if (refreshIntervalSeconds == 0) {
                return loadJwksKeyLoader(CACHE_KEY);
            }

            // Otherwise, get the current JWKSKeyLoader from cache, which will trigger a refresh if needed
            return jwksCache.get(CACHE_KEY);
        } catch (RuntimeException e) {
            LOGGER.warn(e, WARN.JWKS_REFRESH_ERROR.format(e.getMessage()));
            // Return an empty key loader on exception
            return new JWKSKeyLoader(EMPTY_JWKS);
        }
    }


    /**
     * Loads a JWKSKeyLoader from the endpoint. This method is used by the LoadingCache.
     * Implements HTTP 304 "Not Modified" handling, content-based caching, and fallback to last valid result.
     *
     * @param key the cache key (ignored)
     * @return a JWKSKeyLoader instance with the current JWKS content, or the last valid result if available, or an empty one if an error occurs
     */
    private JWKSKeyLoader loadJwksKeyLoader(String key) {
        LOGGER.debug(DEBUG.REFRESHING_KEYS.format(jwksUri.toString()));

        try {
            // Build the request with If-None-Match header if we have a previous etag
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(jwksUri)
                    .timeout(Duration.ofSeconds(DEFAULT_REQUEST_TIMEOUT_SECONDS))
                    .GET();

            // Add If-None-Match header if we have a last valid result with an etag
            if (lastValidResult != null && lastValidResult.getEtag() != null) {
                requestBuilder.header("If-None-Match", lastValidResult.getEtag());
                LOGGER.debug(DEBUG.ADDING_IF_NONE_MATCH_HEADER.format(lastValidResult.getEtag()));
            }

            HttpRequest request = requestBuilder.build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // Handle 304 Not Modified response
            if (response.statusCode() == 304) {
                LOGGER.debug(DEBUG.RECEIVED_304_NOT_MODIFIED::format);
                return lastValidResult;
            }

            if (response.statusCode() != HTTP_OK) {
                LOGGER.warn(WARN.JWKS_FETCH_FAILED.format(response.statusCode()));
                // Fallback to last valid result if available
                if (lastValidResult != null && lastValidResult.isNotEmpty()) {
                    LOGGER.warn(WARN.FALLBACK_TO_LAST_VALID_JWKS_HTTP_ERROR.format(response.statusCode()));
                    return lastValidResult;
                }
                return new JWKSKeyLoader(EMPTY_JWKS);
            }

            String jwksContent = response.body();
            LOGGER.debug(DEBUG.FETCHED_JWKS.format(jwksUri.toString()));

            // Get ETag from response headers
            String etag = response.headers().firstValue("ETag").orElse(null);

            // Content-based caching: if content hasn't changed and we have a valid previous result, return it
            if (lastValidResult != null &&
                    lastValidResult.isNotEmpty() &&
                    jwksContent.equals(lastValidResult.getOriginalString())) {
                LOGGER.debug(DEBUG.CONTENT_UNCHANGED::format);
                return lastValidResult;
            }

            // Create new JWKSKeyLoader with the content and etag
            JWKSKeyLoader newLoader = new JWKSKeyLoader(jwksContent, etag);

            // Only update lastValidResult if the new loader has valid keys
            if (newLoader.isNotEmpty()) {
                lastValidResult = newLoader;
            } else if (lastValidResult != null && lastValidResult.isNotEmpty()) {
                // If new loader is empty but we have a valid previous result, log warning and return previous
                LOGGER.warn(WARN.FALLBACK_TO_LAST_VALID_JWKS_EMPTY::format);
                return lastValidResult;
            }

            return newLoader;
        } catch (InterruptedException e) {
            LOGGER.warn(e, WARN.FAILED_TO_FETCH_JWKS.format(jwksUri.toString()));
            // Preserve the interrupt status
            Thread.currentThread().interrupt();
            // Fallback to last valid result if available
            if (lastValidResult != null && lastValidResult.isNotEmpty()) {
                LOGGER.warn(WARN.FALLBACK_TO_LAST_VALID_JWKS_INTERRUPTED::format);
                return lastValidResult;
            }
            return new JWKSKeyLoader(EMPTY_JWKS);
        } catch (IOException | SecurityException | IllegalArgumentException e) {
            LOGGER.warn(e, WARN.FAILED_TO_FETCH_JWKS.format(jwksUri.toString()));
            // Fallback to last valid result if available
            if (lastValidResult != null && lastValidResult.isNotEmpty()) {
                LOGGER.warn(WARN.FALLBACK_TO_LAST_VALID_JWKS_EXCEPTION.format(e.getMessage()));
                return lastValidResult;
            }
            return new JWKSKeyLoader(EMPTY_JWKS);
        }
    }


    @Override
    public Optional<KeyInfo> getKeyInfo(String kid) {
        if (MoreStrings.isEmpty(kid)) {
            LOGGER.debug(DEBUG.KEY_ID_EMPTY.format());
            return Optional.empty();
        }

        // First try to get the key info from the current loader
        Optional<KeyInfo> keyInfo = resolve().getKeyInfo(kid);

        // If key info not found, force a refresh and try again
        if (keyInfo.isEmpty()) {
            LOGGER.debug(DEBUG.KEY_NOT_FOUND_REFRESHING.format(kid));
            jwksCache.invalidate(CACHE_KEY);
            keyInfo = resolve().getKeyInfo(kid);
        }

        return keyInfo;
    }

    @Override
    public Optional<KeyInfo> getFirstKeyInfo() {
        return resolve().getFirstKeyInfo();
    }

    @Override
    public List<KeyInfo> getAllKeyInfos() {
        return resolve().getAllKeyInfos();
    }


    @Override
    public Set<String> keySet() {
        return resolve().keySet();
    }

}
