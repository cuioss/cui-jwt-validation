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
import java.security.Key;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import static de.cuioss.jwt.token.JWTTokenLogMessages.WARN;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from an HTTP endpoint.
 * Uses Caffeine cache for caching keys.
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

    private final URI jwksUri;
    private final int refreshIntervalSeconds;
    private final LoadingCache<String, JWKSKeyLoader> jwksCache;
    private final HttpClient httpClient;

    /**
     * Creates a new HttpJwksLoader with the specified JWKS URL and refresh interval.
     *
     * @param jwksUrl                the URL of the JWKS endpoint
     * @param refreshIntervalSeconds the interval in seconds at which to refresh the keys
     * @param sslContext             optional SSLContext for secure connections, if null the default SSLContext from VM configuration is used
     */
    public HttpJwksLoader(@NonNull String jwksUrl, int refreshIntervalSeconds, SSLContext sslContext) {
        this.jwksUri = validateAndCreateUri(jwksUrl);
        this.refreshIntervalSeconds = validateRefreshInterval(refreshIntervalSeconds);
        this.httpClient = createHttpClient(sslContext);
        this.jwksCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(refreshIntervalSeconds))
                .refreshAfterWrite(Duration.ofSeconds(refreshIntervalSeconds))
                .build(this::loadJwksKeyLoader);

        // Initial JWKS content fetch to populate cache
        jwksCache.get(CACHE_KEY);

        LOGGER.debug("Initialized HttpJwksLoader with URL: %s, refresh interval: %s seconds",
                jwksUri.toString(), refreshIntervalSeconds);
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
     * Validates the refresh interval.
     *
     * @param refreshIntervalSeconds the refresh interval in seconds
     * @return the validated refresh interval
     * @throws IllegalArgumentException if the refresh interval is not positive
     */
    private int validateRefreshInterval(int refreshIntervalSeconds) {
        if (refreshIntervalSeconds <= 0) {
            throw new IllegalArgumentException("Refresh interval must be greater than zero");
        }
        return refreshIntervalSeconds;
    }

    /**
     * Creates an HTTP client with the specified SSL context.
     *
     * @param sslContext the SSL context to use, or null to use the default
     * @return the HTTP client
     */
    private HttpClient createHttpClient(SSLContext sslContext) {
        HttpClient.Builder httpClientBuilder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS));

        if (sslContext != null) {
            httpClientBuilder.sslContext(sslContext);
            LOGGER.debug("Using provided SSL context");
        }

        return httpClientBuilder.build();
    }

    /**
     * Resolves a JWKSKeyLoader for the current JWKS content.
     * This method gets the current JWKSKeyLoader from the cache, which will trigger a refresh if needed.
     *
     * @return a JWKSKeyLoader instance with the current JWKS content
     */
    public JWKSKeyLoader resolve() {
        LOGGER.debug("Resolving key loader for JWKS endpoint: %s", jwksUri.toString());

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
        LOGGER.debug("Refreshing keys from JWKS endpoint: %s", jwksUri.toString());

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
            LOGGER.debug("Successfully fetched JWKS from URL: %s", jwksUri.toString());
            return new JWKSKeyLoader(jwksContent);
        } catch (InterruptedException e) {
            LOGGER.warn(e, "Failed to fetch JWKS from URL: %s", jwksUri.toString());
            // Preserve the interrupt status
            Thread.currentThread().interrupt();
            return new JWKSKeyLoader(EMPTY_JWKS);
        } catch (IOException | SecurityException | IllegalArgumentException e) {
            LOGGER.warn(e, "Failed to fetch JWKS from URL: %s", jwksUri.toString());
            return new JWKSKeyLoader(EMPTY_JWKS);
        }
    }


    @Override
    public Optional<Key> getKey(String kid) {
        if (MoreStrings.isEmpty(kid)) {
            LOGGER.debug("Key ID is null or empty");
            return Optional.empty();
        }

        // First try to get the key from the current loader
        Optional<Key> key = resolve().getKey(kid);

        // If key not found, force a refresh and try again
        if (key.isEmpty()) {
            LOGGER.debug("Key with ID %s not found, refreshing keys", kid);
            jwksCache.invalidate(CACHE_KEY);
            key = resolve().getKey(kid);
        }

        return key;
    }

    @Override
    public Optional<Key> getFirstKey() {
        return resolve().getFirstKey();
    }

    @Override
    public Set<String> keySet() {
        return resolve().keySet();
    }

}
