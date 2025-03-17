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
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.net.ssl.SSLContext;

import static de.cuioss.jwt.token.PortalTokenLogMessages.WARN;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from an HTTP endpoint.
 * Uses Caffeine cache for caching keys.
 * 
 * @author Oliver Wolff
 */
@ToString(exclude = {"keyCache"})
@EqualsAndHashCode(exclude = {"keyCache"}, callSuper = false)
public class HttpJwksLoader extends AbstractJwksLoader {

    private static final int DEFAULT_TIMEOUT_SECONDS = 10;

    private final URI jwksUri;
    private final int refreshIntervalSeconds;
    private final LoadingCache<String, Key> keyCache;
    private final HttpClient httpClient;

    /**
     * Creates a new HttpJwksLoader with the specified JWKS URL and refresh interval.
     *
     * @param jwksUrl the URL of the JWKS endpoint
     * @param refreshIntervalSeconds the interval in seconds at which to refresh the keys
     * @param sslContext optional SSLContext for secure connections, if null the default SSLContext from VM configuration is used
     */
    public HttpJwksLoader(@NonNull String jwksUrl, int refreshIntervalSeconds, SSLContext sslContext) {
        // Validate URL format and create URI
        URI uri;
        try {
            uri = URI.create(jwksUrl);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid JWKS URL: " + jwksUrl, e);
        }

        this.jwksUri = uri;
        if (refreshIntervalSeconds <= 0) {
            throw new IllegalArgumentException("Refresh interval must be greater than zero");
        }
        this.refreshIntervalSeconds = refreshIntervalSeconds;

        // Create HTTP client with SSL context if provided
        HttpClient.Builder httpClientBuilder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS));

        // If sslContext is provided, use it, otherwise use the default from VM configuration
        if (sslContext != null) {
            httpClientBuilder.sslContext(sslContext);
            LOGGER.debug("Using provided SSL context");
        }

        this.httpClient = httpClientBuilder.build();

        // Initialize Caffeine cache with automatic loading and refreshing
        this.keyCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(refreshIntervalSeconds))
                .refreshAfterWrite(Duration.ofSeconds(refreshIntervalSeconds))
                .build(this::loadKey);

        // Initial key fetch to populate cache
        refreshKeys();

        LOGGER.debug("Initialized HttpJwksLoader with URL: %s, refresh interval: %s seconds",
                jwksUri.toString(), refreshIntervalSeconds);
    }


    @Override
    public Optional<Key> getKey(String kid) {
        if (kid == null) {
            LOGGER.debug("Key ID is null");
            return Optional.empty();
        }

        try {
            Key key = keyCache.get(kid);
            return Optional.ofNullable(key);
        } catch (Exception e) {
            LOGGER.debug("Error loading key with ID: %s, %s", kid, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public Optional<Key> getFirstKey() {
        Map<String, Key> snapshot = keyCache.asMap();
        if (snapshot.isEmpty()) {
            LOGGER.debug("No keys available, refreshing keys");
            refreshKeys();
            snapshot = keyCache.asMap();
        }

        if (snapshot.isEmpty()) {
            return Optional.empty();
        }

        // Return the first key in the cache
        return Optional.of(snapshot.values().iterator().next());
    }

    @Override
    public void refreshKeys() {
        LOGGER.debug("Refreshing keys from JWKS endpoint: %s", jwksUri.toString());
        try {
            String jwksContent;

            // Handle as HTTP URL
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(jwksUri)
                        .timeout(Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS))
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() != 200) {
                    LOGGER.warn(WARN.JWKS_FETCH_FAILED.format(response.statusCode()));
                    // Don't clear keys on server error, keep using the existing keys
                    return;
                }

                jwksContent = response.body();
                LOGGER.debug("Successfully fetched JWKS from URL: %s", jwksUri.toString());
            } catch (Exception e) {
                LOGGER.warn(e, "Failed to fetch JWKS from URL: %s", jwksUri.toString());
                return;
            }

            Map<String, Key> newKeys = parseJwks(jwksContent);
            if (!newKeys.isEmpty()) {
                // Only replace keys if we successfully parsed at least one key
                keyCache.invalidateAll();
                newKeys.forEach(keyCache::put);
            }
            LOGGER.debug("Successfully refreshed %s keys", keyCache.estimatedSize());
        } catch (Exception e) {
            LOGGER.warn(e, WARN.JWKS_REFRESH_ERROR.format(e.getMessage()));
            // Don't clear keys on exception, keep using the existing keys
        }
    }

    /**
     * Loads a key by its ID. This method is used by the LoadingCache.
     *
     * @param kid the key ID
     * @return the key if found, null otherwise
     */
    private Key loadKey(String kid) {
        LOGGER.debug("Loading key with ID: %s", kid);

        // Refresh keys if needed
        refreshKeys();

        // Get the key from the cache's internal map
        Map<String, Key> keys = keyCache.asMap();
        return keys.get(kid);
    }

    @Override
    public Set<String> keySet() {
        return keyCache.asMap().keySet();
    }

}
