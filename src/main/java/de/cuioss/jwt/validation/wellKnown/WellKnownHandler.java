package de.cuioss.jwt.validation.wellKnown;

import de.cuioss.tools.logging.CuiLogger;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
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
 * The implementation uses {@link java.net.HttpURLConnection} for fetching the
 * discovery document and {@link jakarta.json.Json} for parsing the JSON response.
 * </p>
 * <p>
 * Issuer validation is performed to ensure the 'issuer' claim in the discovery
 * document is consistent with the .well-known URL from which it was fetched.
 * </p>
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@EqualsAndHashCode
@ToString
public final class WellKnownHandler {

    private static final CuiLogger log = new CuiLogger(WellKnownHandler.class);

    private static final String ISSUER_KEY = "issuer";
    private static final String JWKS_URI_KEY = "jwks_uri";
    private static final String AUTHORIZATION_ENDPOINT_KEY = "authorization_endpoint";
    private static final String TOKEN_ENDPOINT_KEY = "token_endpoint";
    private static final String USERINFO_ENDPOINT_KEY = "userinfo_endpoint";

    private static final int CONNECT_TIMEOUT_MS = 5000; // 5 seconds
    private static final int READ_TIMEOUT_MS = 5000;    // 5 seconds

    private final Map<String, URL> endpoints;

    @Getter
    private final URL wellKnownUrl;

    /**
     * Creates a new {@link WellKnownHandler} by fetching and parsing the
     * OIDC discovery document from the given .well-known URL string.
     *
     * @param wellKnownUrlString The string representation of the .well-known/openid-configuration URL.
     *                           Must not be null or empty.
     * @return A new {@link WellKnownHandler} instance.
     * @throws WellKnownDiscoveryException If any error occurs during discovery,
     *                                     parsing, or validation (e.g., network issues,
     *                                     malformed JSON, invalid issuer).
     */
    public static WellKnownHandler fromWellKnownUrl(String wellKnownUrlString) {
        if (wellKnownUrlString == null || wellKnownUrlString.trim().isEmpty()) {
            throw new WellKnownDiscoveryException("Well-known URL string must not be null or empty.");
        }

        URL wellKnownUrl;
        try {
            wellKnownUrl = new URL(wellKnownUrlString);
        } catch (MalformedURLException e) {
            throw new WellKnownDiscoveryException("Invalid .well-known URL: " + wellKnownUrlString, e);
        }

        log.debug("Fetching OpenID Connect discovery document from: {}", wellKnownUrl);

        HttpURLConnection connection = null;
        InputStream inputStream = null;
        JsonObject discoveryDocument;

        try {
            connection = (HttpURLConnection) wellKnownUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            connection.setRequestProperty("Accept", "application/json");

            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new WellKnownDiscoveryException(
                    "Failed to fetch discovery document from " + wellKnownUrl + ". HTTP Status: " + responseCode);
            }

            inputStream = connection.getInputStream();
            try (JsonReader jsonReader = Json.createReader(inputStream)) {
                discoveryDocument = jsonReader.readObject();
            } catch (Exception e) {
                throw new WellKnownDiscoveryException("Failed to parse JSON from " + wellKnownUrl, e);
            }

        } catch (IOException e) {
            throw new WellKnownDiscoveryException("IOException while fetching or reading from " + wellKnownUrl, e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    log.warn("Failed to close input stream for {}", wellKnownUrl, e);
                }
            }
            if (connection != null) {
                connection.disconnect();
            }
        }

        log.trace("Successfully fetched discovery document: {}", discoveryDocument);

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
        checkAccessibility(parsedEndpoints.get(JWKS_URI_KEY), JWKS_URI_KEY);


        return new WellKnownHandler(parsedEndpoints, wellKnownUrl);
    }

    private static Optional<String> getString(JsonObject jsonObject, String key) {
        if (jsonObject.containsKey(key) && !jsonObject.isNull(key)) {
            JsonString jsonString = jsonObject.getJsonString(key);
            if (jsonString != null) {
                return Optional.of(jsonString.getString());
            }
        }
        return Optional.empty();
    }

    private static void addUrlToMap(Map<String, URL> map, String key, String urlString, URL wellKnownUrl, boolean isRequired) {
        if (urlString == null) {
            if (isRequired) {
                throw new WellKnownDiscoveryException("Required URL field '" + key + "' is missing in discovery document from " + wellKnownUrl);
            }
            log.debug("Optional URL field '{}' is missing in discovery document from {}", key, wellKnownUrl);
            return;
        }
        try {
            map.put(key, new URL(urlString));
        } catch (MalformedURLException e) {
            throw new WellKnownDiscoveryException(
                "Malformed URL for field '" + key + "': " + urlString + " from " + wellKnownUrl, e);
        }
    }

    private static void validateIssuer(String issuerFromDocument, URL wellKnownUrl) {
        log.debug("Validating issuer: Document issuer='{}', WellKnown URL='{}'", issuerFromDocument, wellKnownUrl);
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
            issuerAsUrl = new URL(issuerFromDocument);
        } catch (MalformedURLException e) {
            throw new WellKnownDiscoveryException("Issuer URL from discovery document is malformed: " + issuerFromDocument, e);
        }

        String expectedWellKnownPath;
        if (issuerAsUrl.getPath() == null || issuerAsUrl.getPath().isEmpty() || issuerAsUrl.getPath().equals("/")) {
            expectedWellKnownPath = "/.well-known/openid-configuration";
        } else {
            String issuerPath = issuerAsUrl.getPath();
            if (issuerPath.endsWith("/")) {
                issuerPath = issuerPath.substring(0, issuerPath.length() -1);
            }
            expectedWellKnownPath = issuerPath + "/.well-known/openid-configuration";
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
            log.error(errorMessage);
            throw new WellKnownDiscoveryException(errorMessage);
        }
        log.debug("Issuer validation successful for {}", issuerFromDocument);
    }


    private static void checkAccessibility(URL url, String keyName) {
        if (url == null) {
            return;
        }
        HttpURLConnection connection = null;
        try {
            log.debug("Performing accessibility check for {} URL: {}", keyName, url);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD"); // Or GET, HEAD is lighter
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            connection.connect(); // Explicitly connect to trigger potential errors

            int responseCode = connection.getResponseCode();
            if (responseCode < 200 || responseCode >= 400) { // Check for non-successful responses
                log.warn("Accessibility check for {} URL '{}' returned HTTP status {}. It might be inaccessible.",
                    keyName, url, responseCode);
            } else {
                log.debug("Accessibility check for {} URL '{}' successful (HTTP {}).", keyName, url, responseCode);
            }
        } catch (IOException e) {
            log.warn("Accessibility check for {} URL '{}' failed with IOException: {}. It might be inaccessible.",
                keyName, url, e.getMessage(), e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
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
