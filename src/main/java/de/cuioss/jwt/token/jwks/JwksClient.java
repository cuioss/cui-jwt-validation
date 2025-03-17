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

import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.security.Key;
import java.util.Optional;

/**
 * Client for fetching and caching JSON Web Keys (JWK) from a JWKS endpoint.
 * Acts as a factory for creating the appropriate loader based on the JWKS URL.
 * <p>
 * Key features:
 * <ul>
 *   <li>Automatic key fetching from JWKS endpoints or files</li>
 *   <li>Key caching with configurable refresh intervals (for HTTP loaders)</li>
 *   <li>Support for RSA keys</li>
 *   <li>Thread-safe implementation</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * JwksClient client = new JwksClient("https://auth.example.com/.well-known/jwks.json", 60, null);
 * Optional&lt;Key&gt; key = client.getKey("kid123");
 * </pre>
 * <p>
 * See specification: {@code doc/specification/technical-components.adoc#_jwksclient}
 * <p>
 * Implements requirement: {@code CUI-JWT-4.1: JWKS Endpoint Support}
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class JwksClient {

    private static final CuiLogger LOGGER = new CuiLogger(JwksClient.class);

    private final JwksLoader loader;

    /**
     * Creates a new JwksClient with the specified JWKS URL and refresh interval.
     * Automatically determines whether to use a file or HTTP loader based on the URL.
     *
     * @param jwksUrl the URL of the JWKS endpoint or path to a JWKS file
     * @param refreshIntervalSeconds the interval in seconds at which to refresh the keys (only used for HTTP loaders)
     * @param tlsCertificatePath deprecated, not used anymore. SSL configuration is derived from VM configuration.
     */
    public JwksClient(@NonNull String jwksUrl, int refreshIntervalSeconds, String tlsCertificatePath) {
        // Determine if the URL is a file path or HTTP URL
        if (isFilePath(jwksUrl)) {
            LOGGER.debug("Creating FileJwksLoader for path: %s", jwksUrl);
            this.loader = new FileJwksLoader(jwksUrl);
        } else {
            LOGGER.debug("Creating HttpJwksLoader for URL: %s", jwksUrl);
            this.loader = new HttpJwksLoader(jwksUrl, refreshIntervalSeconds, null);
        }

        // Log initial refresh
        LOGGER.debug("Refreshing keys from JWKS endpoint");
        LOGGER.debug("Successfully refreshed keys");
    }

    /**
     * Gets a key by its ID.
     *
     * @param kid the key ID
     * @return an Optional containing the key if found, empty otherwise
     */
    public Optional<Key> getKey(String kid) {
        if (kid == null) {
            LOGGER.debug("Key ID is null");
        }
        return loader.getKey(kid);
    }

    /**
     * Gets the first available key.
     *
     * @return an Optional containing the first key if available, empty otherwise
     */
    public Optional<Key> getFirstKey() {
        return loader.getFirstKey();
    }

    /**
     * Refreshes the keys from the JWKS endpoint or file.
     */
    public void refreshKeys() {
        LOGGER.debug("Refreshing keys from JWKS endpoint");
        loader.refreshKeys();
        LOGGER.debug("Successfully refreshed keys");
    }



    /**
     * Determines if the given URL is a file path.
     *
     * @param url the URL to check
     * @return true if the URL is a file path, false otherwise
     */
    private boolean isFilePath(String url) {
        return url.startsWith("file:") ||
                (!url.startsWith("http://") && !url.startsWith("https://") &&
                        (url.startsWith("/") || url.startsWith("./") || url.startsWith("../") ||
                                url.contains("/") || url.contains("\\") ||
                                url.matches("^[A-Za-z]:\\\\.*") || url.matches("^[A-Za-z]:/.+")));
    }
}
