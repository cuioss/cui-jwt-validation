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
    private static final int DEFAULT_TIMEOUT_SECONDS = 10;
    private static final String EMPTY_JWKS = "{}";
    private static final String CACHE_KEY = "jwks";
    private static final int HTTP_OK = 200;
    private static final int DEFAULT_REFRESH_INTERVAL_SECONDS = 300; // 5 minutes

    private final URI jwksUri;
    private final int refreshIntervalSeconds;
    private final LoadingCache<String, JWKSKeyLoader> jwksCache;
    private final HttpClient httpClient;

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
        this.jwksCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(refreshIntervalSeconds))
                .refreshAfterWrite(Duration.ofSeconds(refreshIntervalSeconds))
                .build(this::loadJwksKeyLoader);

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
         * If refreshIntervalSeconds is 0, the default value of 300 seconds (5 minutes) will be used.
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

            // Use default refresh interval if none is specified
            int actualRefreshInterval = refreshIntervalSeconds == 0 ? DEFAULT_REFRESH_INTERVAL_SECONDS : refreshIntervalSeconds;

            // Create default SecureSSLContextProvider instance if none is provided
            SecureSSLContextProvider actualSecureSSLContextProvider = secureSSLContextProvider != null ? secureSSLContextProvider : new SecureSSLContextProvider();

            // Get or create a secure SSLContext using the SecureSSLContextProvider configuration
            SSLContext secureContext = actualSecureSSLContextProvider.getOrCreateSecureSSLContext(sslContext);

            return new HttpJwksLoader(jwksUrl, actualRefreshInterval, secureContext);
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
                .connectTimeout(Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS))
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
            // Get the current JWKSKeyLoader from cache, which will trigger a refresh if needed
            return jwksCache.get(CACHE_KEY);
        } catch (RuntimeException e) {
            LOGGER.warn(e, WARN.JWKS_REFRESH_ERROR.format(e.getMessage()));
            // Return an empty key loader on exception
            return new JWKSKeyLoader(EMPTY_JWKS);
        }
    }


    /**
     * Loads a JWKSKeyLoader from the endpoint. This method is used by the LoadingCache.
     *
     * @param key the cache key (ignored)
     * @return a JWKSKeyLoader instance with the current JWKS content, or an empty one if an error occurs
     */
    private JWKSKeyLoader loadJwksKeyLoader(String key) {
        LOGGER.debug(DEBUG.REFRESHING_KEYS.format(jwksUri.toString()));

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(jwksUri)
                    .timeout(Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != HTTP_OK) {
                LOGGER.warn(WARN.JWKS_FETCH_FAILED.format(response.statusCode()));
                return new JWKSKeyLoader(EMPTY_JWKS);
            }

            String jwksContent = response.body();
            LOGGER.debug(DEBUG.FETCHED_JWKS.format(jwksUri.toString()));
            return new JWKSKeyLoader(jwksContent);
        } catch (InterruptedException e) {
            LOGGER.warn(e, WARN.FAILED_TO_FETCH_JWKS.format(jwksUri.toString()));
            // Preserve the interrupt status
            Thread.currentThread().interrupt();
            return new JWKSKeyLoader(EMPTY_JWKS);
        } catch (IOException | SecurityException | IllegalArgumentException e) {
            LOGGER.warn(e, WARN.FAILED_TO_FETCH_JWKS.format(jwksUri.toString()));
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
