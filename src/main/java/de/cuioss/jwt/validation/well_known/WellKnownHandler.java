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
package de.cuioss.jwt.validation.well_known;

import de.cuioss.jwt.validation.security.SecureSSLContextProvider;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Handles the discovery of OpenID Connect (OIDC) Provider metadata from a
 * .well-known/openid-configuration endpoint.
 * <p>
 * This class fetches, parses, and validates the OIDC discovery document.
 * It provides access to the discovered endpoint URLs like {@code jwks_uri},
 * {@code authorization_endpoint}, etc.
 * </p>
 * <p>
 * The implementation uses {@link java.net.http.HttpClient} for fetching the
 * discovery document and {@link jakarta.json.Json} for parsing the JSON response.
 * </p>
 * <p>
 * Issuer validation is performed to ensure the 'issuer' claim in the discovery
 * document is consistent with the .well-known URL from which it was fetched.
 * </p>
 * <p>
 * Use the builder to create instances of this class:
 * <pre>
 * WellKnownHandler handler = WellKnownHandler.builder()
 *     .wellKnownUrl("https://example.com/.well-known/openid-configuration")
 *     .build();
 * </pre>
 * </p>
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@EqualsAndHashCode
@ToString
@Builder(builderClassName = "WellKnownHandlerBuilder", access = AccessLevel.PRIVATE)
public final class WellKnownHandler {

    private static final CuiLogger LOGGER = new CuiLogger(WellKnownHandler.class);

    private static final String ISSUER_KEY = "issuer";
    private static final String JWKS_URI_KEY = "jwks_uri";
    private static final String AUTHORIZATION_ENDPOINT_KEY = "authorization_endpoint";
    private static final String TOKEN_ENDPOINT_KEY = "token_endpoint";
    private static final String USERINFO_ENDPOINT_KEY = "userinfo_endpoint";

    private static final int TIMEOUT_SECONDS = 5; // 5 seconds
    public static final String WELL_KNOWN_OPENID_CONFIGURATION = "/.well-known/openid-configuration";

    private final Map<String, URL> endpoints;

    @Getter
    private final URL wellKnownUrl;

    /**
     * Returns a new builder for creating a {@link WellKnownHandler} instance.
     *
     * @return A new builder instance.
     */
    public static WellKnownHandlerBuilder builder() {
        return new WellKnownHandlerBuilder();
    }


    /**
     * Builder for creating {@link WellKnownHandler} instances.
     */
    public static class WellKnownHandlerBuilder {
        private URL wellKnownUrl;
        private String wellKnownUrlString;
        private SSLContext sslContext;
        private SecureSSLContextProvider secureSSLContextProvider;

        /**
         * Sets the well-known URL as a string.
         *
         * @param wellKnownUrlString The string representation of the .well-known/openid-configuration URL.
         *                           Must not be null or empty.
         * @return This builder instance.
         */
        public WellKnownHandlerBuilder wellKnownUrl(String wellKnownUrlString) {
            this.wellKnownUrlString = wellKnownUrlString;
            return this;
        }

        /**
         * Sets the well-known URL directly.
         * <p>
         * Note: If both URL and string are set, the URL takes precedence.
         * </p>
         *
         * @param wellKnownUrl The URL of the .well-known/openid-configuration endpoint.
         *                     Must not be null.
         * @return This builder instance.
         */
        public WellKnownHandlerBuilder wellKnownUrl(URL wellKnownUrl) {
            this.wellKnownUrl = wellKnownUrl;
            return this;
        }

        /**
         * Sets the SSL context to use for HTTPS connections.
         * <p>
         * If not set, a default secure SSL context will be created.
         * </p>
         *
         * @param sslContext The SSL context to use.
         * @return This builder instance.
         */
        public WellKnownHandlerBuilder sslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        /**
         * Sets the TLS versions configuration.
         *
         * @param secureSSLContextProvider The TLS versions configuration to use.
         * @return This builder instance.
         */
        public WellKnownHandlerBuilder tlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            this.secureSSLContextProvider = secureSSLContextProvider;
            return this;
        }

        /**
         * Parses a JSON response string into a JsonObject.
         *
         * @param responseBody The JSON response string to parse
         * @param wellKnownUrl The well-known URL (used for error messages)
         * @return The parsed JsonObject
         * @throws WellKnownDiscoveryException If parsing fails
         */
        private JsonObject parseJsonResponse(String responseBody, URL wellKnownUrl) {
            try (JsonReader jsonReader = Json.createReader(new StringReader(responseBody))) {
                return jsonReader.readObject();
            } catch (Exception e) {
                throw new WellKnownDiscoveryException("Failed to parse JSON from " + wellKnownUrl, e);
            }
        }

        /**
         * Extracts a string value from a JsonObject.
         *
         * @param jsonObject The JsonObject to extract from
         * @param key The key to extract
         * @return An Optional containing the string value, or empty if not found
         */
        private Optional<String> getString(JsonObject jsonObject, String key) {
            if (jsonObject.containsKey(key) && !jsonObject.isNull(key)) {
                JsonString jsonString = jsonObject.getJsonString(key);
                if (jsonString != null) {
                    return Optional.of(jsonString.getString());
                }
            }
            return Optional.empty();
        }

        /**
         * Adds a URL to the map of endpoints.
         *
         * @param map The map to add to
         * @param key The key for the URL
         * @param urlString The URL string to add
         * @param wellKnownUrl The well-known URL (used for error messages)
         * @param isRequired Whether this URL is required
         */
        private void addUrlToMap(Map<String, URL> map, String key, String urlString, URL wellKnownUrl, boolean isRequired) {
            if (urlString == null) {
                if (isRequired) {
                    throw new WellKnownDiscoveryException("Required URL field '" + key + "' is missing in discovery document from " + wellKnownUrl);
                }
                LOGGER.debug("Optional URL field '{}' is missing in discovery document from {}", key, wellKnownUrl);
                return;
            }
            try {
                map.put(key, URI.create(urlString).toURL());
            } catch (MalformedURLException | IllegalArgumentException e) {
                throw new WellKnownDiscoveryException(
                        "Malformed URL for field '" + key + "': " + urlString + " from " + wellKnownUrl, e);
            }
        }

        /**
         * Validates that the issuer from the discovery document matches the well-known URL.
         *
         * @param issuerFromDocument The issuer from the discovery document
         * @param wellKnownUrl The well-known URL
         */
        private void validateIssuer(String issuerFromDocument, URL wellKnownUrl) {
            LOGGER.debug("Validating issuer: Document issuer='{}', WellKnown URL='{}'", issuerFromDocument, wellKnownUrl);
            // The OpenID Connect Discovery 1.0 spec, section 4.3 states:
            // "The issuer value returned MUST be identical to the Issuer URL that was
            // used as the prefix to /.well-known/openid-configuration to retrieve the
            // configuration information."
            // A simple check is to see if the wellKnownUrl starts with the issuer string,
            // and that the path component matches.
            // For example, if issuer is "https://example.com", wellKnownUrl should be "https://example.com/.well-known/openid-configuration"
            // If issuer is "https://example.com/path", wellKnownUrl should be "https://example.com/path/.well-known/openid-configuration"

            URL issuerAsUrl;
            try {
                issuerAsUrl = URI.create(issuerFromDocument).toURL();
            } catch (MalformedURLException | IllegalArgumentException e) {
                throw new WellKnownDiscoveryException("Issuer URL from discovery document is malformed: " + issuerFromDocument, e);
            }

            String expectedWellKnownPath;
            if (issuerAsUrl.getPath() == null || issuerAsUrl.getPath().isEmpty() || "/".equals(issuerAsUrl.getPath())) {
                expectedWellKnownPath = WELL_KNOWN_OPENID_CONFIGURATION;
            } else {
                String issuerPath = issuerAsUrl.getPath();
                if (issuerPath.endsWith("/")) {
                    issuerPath = issuerPath.substring(0, issuerPath.length() - 1);
                }
                expectedWellKnownPath = issuerPath + WELL_KNOWN_OPENID_CONFIGURATION;
            }


            boolean schemeMatch = issuerAsUrl.getProtocol().equals(wellKnownUrl.getProtocol());
            boolean hostMatch = issuerAsUrl.getHost().equalsIgnoreCase(wellKnownUrl.getHost());
            int issuerPort = issuerAsUrl.getPort() == -1 ? issuerAsUrl.getDefaultPort() : issuerAsUrl.getPort();
            int wellKnownPort = wellKnownUrl.getPort() == -1 ? wellKnownUrl.getDefaultPort() : wellKnownUrl.getPort();
            boolean portMatch = issuerPort == wellKnownPort;
            boolean pathMatch = wellKnownUrl.getPath().equals(expectedWellKnownPath);


            if (!(schemeMatch && hostMatch && portMatch && pathMatch)) {
                String errorMessage = String.format(
                        "Issuer validation failed. Document issuer '%s' (normalized to base URL for .well-known: %s://%s%s%s) " +
                                "does not match the .well-known URL '%s'. " +
                                "Expected path for .well-known: '%s'. " +
                                "SchemeMatch=%b, HostMatch=%b, PortMatch=%b (IssuerPort=%d, WellKnownPort=%d), PathMatch=%b (WellKnownPath='%s')",
                        issuerFromDocument, issuerAsUrl.getProtocol(), issuerAsUrl.getHost(),
                        (issuerAsUrl.getPort() != -1 ? ":" + issuerAsUrl.getPort() : ""),
                        (issuerAsUrl.getPath() == null ? "" : issuerAsUrl.getPath()),
                        wellKnownUrl.toString(),
                        expectedWellKnownPath,
                        schemeMatch, hostMatch, portMatch, issuerPort, wellKnownPort, pathMatch, wellKnownUrl.getPath());
                LOGGER.error(errorMessage);
                throw new WellKnownDiscoveryException(errorMessage);
            }
            LOGGER.debug("Issuer validation successful for {}", issuerFromDocument);
        }

        /**
         * Checks if a URL is accessible.
         *
         * @param url The URL to check
         * @param keyName The name of the key (for logging)
         * @param sslContext The SSL context to use
         */
        private void checkAccessibility(URL url, String keyName, SSLContext sslContext) {
            if (url == null) {
                return;
            }
            try {
                LOGGER.debug("Performing accessibility check for {} URL: {}", keyName, url);

                HttpClient.Builder httpClientBuilder = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(TIMEOUT_SECONDS));

                // Use the provided SSL context if available
                if (sslContext != null) {
                    httpClientBuilder.sslContext(sslContext);
                }

                HttpClient httpClient = httpClientBuilder.build();

                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(url.toURI())
                        .timeout(Duration.ofSeconds(TIMEOUT_SECONDS));

                // Use GET instead of HEAD if the system property is set (for testing)
                if (USE_GET_FOR_ACCESSIBILITY_CHECK) {
                    requestBuilder.GET();
                    LOGGER.debug("Using GET method for accessibility check (test mode)");
                } else {
                    requestBuilder.method("HEAD", HttpRequest.BodyPublishers.noBody());
                    LOGGER.debug("Using HEAD method for accessibility check");
                }

                HttpRequest request = requestBuilder.build();

                HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());

                int responseCode = response.statusCode();
                if (responseCode < 200 || responseCode >= 400) { // Check for non-successful responses
                    LOGGER.warn("Accessibility check for {} URL '{}' returned HTTP status {}. It might be inaccessible.",
                            keyName, url, responseCode);
                } else {
                    LOGGER.debug("Accessibility check for {} URL '{}' successful (HTTP {}).", keyName, url, responseCode);
                }
            } catch (IOException e) {
                LOGGER.warn("Accessibility check for {} URL '{}' failed with IOException: {}. It might be inaccessible.",
                        keyName, url, e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.warn("Accessibility check for {} URL '{}' was interrupted: {}. It might be inaccessible.",
                        keyName, url, e.getMessage(), e);
            } catch (Exception e) {
                LOGGER.warn("Accessibility check for {} URL '{}' failed with exception: {}. It might be inaccessible.",
                        keyName, url, e.getMessage(), e);
            }
        }

        private static final boolean USE_GET_FOR_ACCESSIBILITY_CHECK = Boolean.getBoolean("de.cuioss.jwt.validation.useGetForAccessibilityCheck");

        /**
         * Builds a new {@link WellKnownHandler} instance with the configured parameters.
         *
         * @return A new {@link WellKnownHandler} instance.
         * @throws WellKnownDiscoveryException If any error occurs during discovery,
         *                                     parsing, or validation (e.g., network issues,
         *                                     malformed JSON, invalid issuer).
         */
        public WellKnownHandler build() {
            // Validate and resolve the well-known URL
            if (wellKnownUrl == null) {
                if (wellKnownUrlString == null || wellKnownUrlString.trim().isEmpty()) {
                    throw new WellKnownDiscoveryException("Well-known URL string must not be null or empty.");
                }

                try {
                    wellKnownUrl = URI.create(wellKnownUrlString).toURL();
                } catch (MalformedURLException | IllegalArgumentException e) {
                    throw new WellKnownDiscoveryException("Invalid .well-known URL: " + wellKnownUrlString, e);
                }
            }

            LOGGER.debug("Fetching OpenID Connect discovery document from: {}", wellKnownUrl);

            JsonObject discoveryDocument;
            SSLContext secureContext = null;

            try {
                // Create a secure SSL context if needed
                SecureSSLContextProvider actualSecureSSLContextProvider = secureSSLContextProvider != null ?
                        secureSSLContextProvider : new SecureSSLContextProvider();
                secureContext = actualSecureSSLContextProvider.getOrCreateSecureSSLContext(sslContext);

                HttpClient httpClient = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                        .sslContext(secureContext)
                        .build();

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(wellKnownUrl.toURI())
                        .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                        .header("Accept", "application/json")
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                int responseCode = response.statusCode();
                if (responseCode != 200) { // HTTP_OK
                    throw new WellKnownDiscoveryException(
                            "Failed to fetch discovery document from " + wellKnownUrl + ". HTTP Status: " + responseCode);
                }

                String responseBody = response.body();
                discoveryDocument = parseJsonResponse(responseBody, wellKnownUrl);

            } catch (IOException e) {
                throw new WellKnownDiscoveryException("IOException while fetching or reading from " + wellKnownUrl, e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new WellKnownDiscoveryException("Interrupted while fetching from " + wellKnownUrl, e);
            } catch (Exception e) {
                throw new WellKnownDiscoveryException("Error while fetching from " + wellKnownUrl, e);
            }

            LOGGER.trace("Successfully fetched discovery document: {}", discoveryDocument);

            Map<String, URL> parsedEndpoints = new HashMap<>();

            // Issuer (Required)
            String issuerString = getString(discoveryDocument, ISSUER_KEY)
                    .orElseThrow(() -> new WellKnownDiscoveryException("Required field 'issuer' not found in discovery document from " + wellKnownUrl));
            validateIssuer(issuerString, wellKnownUrl);
            addUrlToMap(parsedEndpoints, ISSUER_KEY, issuerString, wellKnownUrl, true);

            // JWKS URI (Required)
            addUrlToMap(parsedEndpoints, JWKS_URI_KEY, getString(discoveryDocument, JWKS_URI_KEY).orElse(null), wellKnownUrl, true);

            // Optional endpoints
            addUrlToMap(parsedEndpoints, AUTHORIZATION_ENDPOINT_KEY, getString(discoveryDocument, AUTHORIZATION_ENDPOINT_KEY).orElse(null), wellKnownUrl, false);
            addUrlToMap(parsedEndpoints, TOKEN_ENDPOINT_KEY, getString(discoveryDocument, TOKEN_ENDPOINT_KEY).orElse(null), wellKnownUrl, false);
            addUrlToMap(parsedEndpoints, USERINFO_ENDPOINT_KEY, getString(discoveryDocument, USERINFO_ENDPOINT_KEY).orElse(null), wellKnownUrl, false);

            // Accessibility check for jwks_uri (optional but recommended)
            checkAccessibility(parsedEndpoints.get(JWKS_URI_KEY), JWKS_URI_KEY, secureContext);

            return new WellKnownHandler(parsedEndpoints, wellKnownUrl);
        }
    }

    /**
     * @return An {@link Optional} containing the JWKS URI, or empty if not present.
     */
    public Optional<URL> getJwksUri() {
        return Optional.ofNullable(endpoints.get(JWKS_URI_KEY));
    }

    /**
     * @return An {@link Optional} containing the Authorization Endpoint URI, or empty if not present.
     */
    public Optional<URL> getAuthorizationEndpoint() {
        return Optional.ofNullable(endpoints.get(AUTHORIZATION_ENDPOINT_KEY));
    }

    /**
     * @return An {@link Optional} containing the Token Endpoint URI, or empty if not present.
     */
    public Optional<URL> getTokenEndpoint() {
        return Optional.ofNullable(endpoints.get(TOKEN_ENDPOINT_KEY));
    }

    /**
     * @return An {@link Optional} containing the UserInfo Endpoint URI, or empty if not present.
     */
    public Optional<URL> getUserinfoEndpoint() {
        return Optional.ofNullable(endpoints.get(USERINFO_ENDPOINT_KEY));
    }

    /**
     * @return An {@link Optional} containing the Issuer URI, or empty if not present (should always be present).
     */
    public Optional<URL> getIssuer() {
        return Optional.ofNullable(endpoints.get(ISSUER_KEY));
    }
}
