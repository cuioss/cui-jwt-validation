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

import static de.cuioss.jwt.token.PortalTokenLogMessages.WARN;

import de.cuioss.tools.logging.CuiLogger;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.math.BigInteger;

/**
 * Client for fetching and caching JSON Web Keys (JWK) from a JWKS endpoint.
 * Provides automatic key rotation and caching capabilities.
 * <p>
 * Key features:
 * <ul>
 *   <li>Automatic key fetching from JWKS endpoints</li>
 *   <li>Key caching with configurable refresh intervals</li>
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
@ToString(exclude = {"keys", "scheduler"})
@EqualsAndHashCode(exclude = {"keys", "scheduler"})
public class JwksClient implements AutoCloseable {

    private static final CuiLogger LOGGER = new CuiLogger(JwksClient.class);
    private static final int DEFAULT_TIMEOUT_SECONDS = 10;

    private final String jwksUrl;
    private final int refreshIntervalSeconds;
    private final Map<String, Key> keys = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final HttpClient httpClient;

    /**
     * Creates a new JwksClient with the specified JWKS URL and refresh interval.
     *
     * @param jwksUrl the URL of the JWKS endpoint
     * @param refreshIntervalSeconds the interval in seconds at which to refresh the keys
     * @param tlsCertificatePath optional path to a TLS certificate for secure connections
     */
    public JwksClient(@NonNull String jwksUrl, int refreshIntervalSeconds, String tlsCertificatePath) {
        // Validate URL format
        try {
            URI.create(jwksUrl);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid JWKS URL: " + jwksUrl, e);
        }

        this.jwksUrl = jwksUrl;
        if (refreshIntervalSeconds <= 0) {
            throw new IllegalArgumentException("Refresh interval must be greater than zero");
        }
        this.refreshIntervalSeconds = refreshIntervalSeconds;

        // Create HTTP client
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS))
                .build();

        // Initial key fetch
        refreshKeys();

        // Schedule periodic key refresh
        scheduler.scheduleAtFixedRate(
                this::refreshKeys,
                refreshIntervalSeconds,
                refreshIntervalSeconds,
                TimeUnit.SECONDS);

        LOGGER.debug("Initialized JwksClient with URL: %s, refresh interval: %s seconds", 
                jwksUrl, refreshIntervalSeconds);
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
            return Optional.empty();
        }

        Key key = keys.get(kid);
        if (key == null) {
            LOGGER.debug("No key found with ID: %s, refreshing keys", kid);
            refreshKeys();
            key = keys.get(kid);
        }

        return Optional.ofNullable(key);
    }

    /**
     * Gets the first available key.
     *
     * @return an Optional containing the first key if available, empty otherwise
     */
    public Optional<Key> getFirstKey() {
        if (keys.isEmpty()) {
            LOGGER.debug("No keys available, refreshing keys");
            refreshKeys();
        }

        if (keys.isEmpty()) {
            return Optional.empty();
        }

        // Return the first key in the map
        return Optional.of(keys.values().iterator().next());
    }

    /**
     * Refreshes the keys from the JWKS endpoint.
     */
    public void refreshKeys() {
        LOGGER.debug("Refreshing keys from JWKS endpoint: %s", jwksUrl);
        try {
            String jwksContent;

            // Check if the URL is a file path
            if (jwksUrl.startsWith("file:") || 
                (!jwksUrl.startsWith("http://") && !jwksUrl.startsWith("https://") && 
                 (jwksUrl.startsWith("/") || jwksUrl.startsWith("./") || jwksUrl.startsWith("../") || 
                  jwksUrl.contains("/") || jwksUrl.contains("\\") || 
                  jwksUrl.matches("^[A-Za-z]:\\\\.*") || jwksUrl.matches("^[A-Za-z]:/.+")))) {
                // Handle as file path
                try {
                    java.nio.file.Path path = java.nio.file.Paths.get(jwksUrl);
                    jwksContent = new String(java.nio.file.Files.readAllBytes(path));
                    LOGGER.debug("Successfully read JWKS from file: %s", jwksUrl);
                } catch (IOException e) {
                    LOGGER.warn(e, "Failed to read JWKS from file: %s", jwksUrl);
                    return;
                }
            } else {
                // Handle as HTTP URL
                try {
                    HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create(jwksUrl))
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
                    LOGGER.debug("Successfully fetched JWKS from URL: %s", jwksUrl);
                } catch (Exception e) {
                    LOGGER.warn(e, "Failed to fetch JWKS from URL: %s", jwksUrl);
                    return;
                }
            }

            Map<String, Key> newKeys = parseJwks(jwksContent);
            if (!newKeys.isEmpty()) {
                // Only replace keys if we successfully parsed at least one key
                keys.clear();
                keys.putAll(newKeys);
            }
            LOGGER.debug("Successfully refreshed %s keys", keys.size());
        } catch (Exception e) {
            LOGGER.warn(e, WARN.JWKS_REFRESH_ERROR.format(e.getMessage()));
            // Don't clear keys on exception, keep using the existing keys
        }
    }

    private Map<String, Key> parseJwks(String jwksJson) {
        Map<String, Key> result = new HashMap<>();

        try (JsonReader reader = Json.createReader(new StringReader(jwksJson))) {
            JsonObject jwks = reader.readObject();

            // Check if this is a JWKS with a "keys" array or a single key
            if (jwks.containsKey("keys")) {
                // This is a standard JWKS with a "keys" array
                JsonArray keysArray = jwks.getJsonArray("keys");
                if (keysArray != null) {
                    for (int i = 0; i < keysArray.size(); i++) {
                        JsonObject jwk = keysArray.getJsonObject(i);
                        processKey(jwk, result);
                    }
                }
            } else if (jwks.containsKey("kty")) {
                // This is a single key object
                processKey(jwks, result);
            } else {
                LOGGER.warn("JWKS JSON does not contain 'keys' array or 'kty' field");
            }
        } catch (Exception e) {
            // Handle invalid JSON format
            LOGGER.warn(e, WARN.JWKS_JSON_PARSE_FAILED.format(e.getMessage()));
            // Return empty map to clear existing keys
            return result;
        }

        return result;
    }

    private void processKey(JsonObject jwk, Map<String, Key> result) {
        try {
            String kty = jwk.getString("kty");

            // Generate a key ID if not present
            String kid = jwk.containsKey("kid") ? jwk.getString("kid") : "default-key-id";

            if ("RSA".equals(kty)) {
                try {
                    Key publicKey = parseRsaKey(jwk);
                    result.put(kid, publicKey);
                    LOGGER.debug("Parsed RSA key with ID: %s", kid);
                } catch (Exception e) {
                    LOGGER.warn(e, WARN.RSA_KEY_PARSE_FAILED.format(kid, e.getMessage()));
                }
            } else {
                LOGGER.debug("Unsupported key type: %s for key ID: %s", kty, kid);
            }
        } catch (Exception e) {
            LOGGER.warn(e, "Failed to process key: %s", e.getMessage());
        }
    }

    private Key parseRsaKey(JsonObject jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Check if required fields exist
        if (!jwk.containsKey("n") || !jwk.containsKey("e")) {
            throw new InvalidKeySpecException("JWK is missing required fields 'n' or 'e'");
        }

        // Get the modulus and exponent
        String modulusBase64 = jwk.getString("n");
        String exponentBase64 = jwk.getString("e");

        // Validate Base64 format
        if (!isValidBase64UrlEncoded(modulusBase64) || !isValidBase64UrlEncoded(exponentBase64)) {
            throw new InvalidKeySpecException("Invalid Base64 URL encoded values for 'n' or 'e'");
        }

        // Decode from Base64
        byte[] modulusBytes = Base64.getUrlDecoder().decode(modulusBase64);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(exponentBase64);

        // Convert to BigInteger
        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger exponent = new BigInteger(1, exponentBytes);

        // Create RSA public key
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = factory.generatePublic(spec);

        return publicKey;
    }

    /**
     * Shuts down the client and releases resources.
     */
    public void shutdown() {
        LOGGER.debug("Shutting down JwksClient");
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Closes this resource, relinquishing any underlying resources.
     * This method is invoked automatically on objects managed by the
     * try-with-resources statement.
     */
    @Override
    public void close() {
        shutdown();
    }

    /**
     * Validates if a string is a valid Base64 URL encoded value.
     * 
     * @param value the string to validate
     * @return true if the string is a valid Base64 URL encoded value, false otherwise
     */
    private boolean isValidBase64UrlEncoded(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        // Base64 URL encoded strings should only contain alphanumeric characters, '-', '_', and '='
        return value.matches("^[A-Za-z0-9\\-_]*=*$");
    }
}
