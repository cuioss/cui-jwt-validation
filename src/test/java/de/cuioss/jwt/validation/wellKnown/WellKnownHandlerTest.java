package de.cuioss.jwt.validation.wellKnown;

import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy; // Added for DISCONNECT_AT_START
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
// No changes needed for imports of AssertJ, they are already correct if AssertJ is on classpath.

@EnableMockWebServer
class WellKnownHandlerTest {

    protected MockWebServer mockWebServer;
    protected URIBuilder uriBuilder;
    private OidcDispatcher oidcDispatcher;

    private static final String DEFAULT_OIDC_PATH = "/.well-known/openid-configuration";
    private static final String DEFAULT_JWKS_PATH = "/jwks.json";
    private static final String JSON_CONTENT_TYPE = "application/json;charset=utf-8";

    static class OidcDispatcher extends Dispatcher {
        private String oidcPath = DEFAULT_OIDC_PATH;
        private String jwksPath = DEFAULT_JWKS_PATH; // Default, can be overridden by oidcBody's content
        private String oidcBody;
        private String jwksBody;
        private int oidcStatusCode = 200;
        private int jwksStatusCode = 200;
        private boolean oidcConfigured = false;
        private boolean jwksConfigured = false;
        private final MockWebServer mockWebServer; // To construct dynamic jwks_uri

        public OidcDispatcher(MockWebServer mockWebServer) {
            this.mockWebServer = mockWebServer;
        }

        public void setOidcResponse(String body, int code) {
            this.oidcBody = body;
            this.oidcStatusCode = code;
            this.oidcConfigured = true;
        }

        public void setJwksResponse(String path, String body, int code) {
            this.jwksPath = path; // Allow overriding the JWKS path if needed
            this.jwksBody = body;
            this.jwksStatusCode = code;
            this.jwksConfigured = true;
        }

        @NotNull
        @Override
        public MockResponse dispatch(@NotNull RecordedRequest request) {
            String path = request.getRequestUrl().encodedPath();
            if (oidcPath.equals(path) && oidcConfigured) {
                String dynamicOidcBody = oidcBody;
                if (oidcBody != null && oidcBody.contains("##JWKS_URI##")) {
                    dynamicOidcBody = oidcBody.replace("##JWKS_URI##", mockWebServer.url(jwksPath).toString());
                }
                return new okhttp3.mockwebserver.MockResponse().setResponseCode(oidcStatusCode).setBody(dynamicOidcBody).setHeader("Content-Type", JSON_CONTENT_TYPE);
            } else if (jwksPath.equals(path) && jwksConfigured) {
                okhttp3.mockwebserver.MockResponse resp = new okhttp3.mockwebserver.MockResponse().setResponseCode(jwksStatusCode).setHeader("Content-Type", JSON_CONTENT_TYPE);
                if (request.getMethod().equalsIgnoreCase("HEAD")) {
                    resp.setBody(""); // No body for HEAD
                } else {
                    resp.setBody(jwksBody);
                }
                return resp;
            }
            return new okhttp3.mockwebserver.MockResponse().setResponseCode(404).setBody("Not Found for path: " + path);
        }

        public void reset() {
            oidcBody = null;
            jwksBody = null;
            oidcStatusCode = 200;
            jwksStatusCode = 200;
            oidcPath = DEFAULT_OIDC_PATH;
            jwksPath = DEFAULT_JWKS_PATH;
            oidcConfigured = false;
            jwksConfigured = false;
        }
    }

    @BeforeEach
    void setUp(MockWebServer mockWebServer, URIBuilder uriBuilder) {
        this.mockWebServer = mockWebServer;
        this.uriBuilder = uriBuilder;
        this.oidcDispatcher = new OidcDispatcher(this.mockWebServer);
        this.mockWebServer.setDispatcher(this.oidcDispatcher);
        this.oidcDispatcher.reset(); // Ensure clean state for each test
    }


    private String getFullWellKnownUrl() {
        // Assuming DEFAULT_OIDC_PATH starts with "/", remove it for addPathSegment
        return uriBuilder.addPathSegment(DEFAULT_OIDC_PATH.startsWith("/") ? DEFAULT_OIDC_PATH.substring(1) : DEFAULT_OIDC_PATH).build().toString();
    }

    // Note: getJwksUri() from previous tests is not directly applicable as jwks_uri is now dynamic
    // It will be part of the OIDC config response.

    @Test
    void shouldDiscoverSuccessfully() throws MalformedURLException {
        String serverBaseUrl = uriBuilder.build().toString(); // Base URL of mock server
        String expectedJwksUri = serverBaseUrl.endsWith("/") ? serverBaseUrl + DEFAULT_JWKS_PATH.substring(1) : serverBaseUrl + DEFAULT_JWKS_PATH;

        String authorizationEndpoint = serverBaseUrl + "auth"; // Dynamic based on mock server
        String tokenEndpoint = serverBaseUrl + "token";
        String userinfoEndpoint = serverBaseUrl + "userinfo";

        String oidcConfigJson = String.format(
            "{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\", \"authorization_endpoint\":\"%s\", \"token_endpoint\":\"%s\", \"userinfo_endpoint\":\"%s\"}",
            serverBaseUrl, // Correct issuer
            authorizationEndpoint,
            tokenEndpoint,
            userinfoEndpoint
        );

        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        oidcDispatcher.setJwksResponse(DEFAULT_JWKS_PATH, "{\"keys\":[]}", 200);

        WellKnownHandler handler = WellKnownHandler.fromWellKnownUrl(getFullWellKnownUrl());

        assertThat(handler.getWellKnownUrl().toString()).isEqualTo(getFullWellKnownUrl());
        assertThat(handler.getIssuer()).isPresent().contains(new URL(serverBaseUrl));
        assertThat(handler.getJwksUri()).isPresent().get().asString().isEqualTo(expectedJwksUri);
        assertThat(handler.getAuthorizationEndpoint()).isPresent().contains(new URL(authorizationEndpoint));
        assertThat(handler.getTokenEndpoint()).isPresent().contains(new URL(tokenEndpoint));
        assertThat(handler.getUserinfoEndpoint()).isPresent().contains(new URL(userinfoEndpoint));
    }

    @Test
    void shouldHandleOptionalFieldsMissing() throws MalformedURLException {
        String serverBaseUrl = uriBuilder.build().toString();
        String expectedJwksUri = serverBaseUrl.endsWith("/") ? serverBaseUrl + DEFAULT_JWKS_PATH.substring(1) : serverBaseUrl + DEFAULT_JWKS_PATH;

        String oidcConfigJson = String.format(
            "{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}",
            serverBaseUrl
        );
        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        oidcDispatcher.setJwksResponse(DEFAULT_JWKS_PATH, "{\"keys\":[]}", 200);

        WellKnownHandler handler = WellKnownHandler.fromWellKnownUrl(getFullWellKnownUrl());

        assertThat(handler.getWellKnownUrl().toString()).isEqualTo(getFullWellKnownUrl());
        assertThat(handler.getIssuer()).isPresent().contains(new URL(serverBaseUrl));
        assertThat(handler.getJwksUri()).isPresent().get().asString().isEqualTo(expectedJwksUri);
        assertThat(handler.getAuthorizationEndpoint()).isEmpty();
        assertThat(handler.getTokenEndpoint()).isEmpty();
        assertThat(handler.getUserinfoEndpoint()).isEmpty();
    }

    @Test
    void shouldThrowExceptionForNullUrlString() {
        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(null))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Well-known URL string must not be null or empty.");
    }

    @Test
    void shouldThrowExceptionForEmptyUrlString() {
        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl("  "))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Well-known URL string must not be null or empty.");
    }


    @Test
    void shouldThrowExceptionForMalformedUrl() {
        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl("htp:/invalid-url-format"))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Invalid .well-known URL: htp:/invalid-url-format");
    }

    @Test
    void shouldThrowExceptionForNonExistentWellKnownEndpoint() {
        String fullWellKnownUrl = getFullWellKnownUrl();
        oidcDispatcher.setOidcResponse("Not Found", 404); // Or let it default to 404 by not configuring for the path

        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Failed to fetch discovery document from " + fullWellKnownUrl + ". HTTP Status: 404");
    }

    @Test
    void shouldThrowExceptionForServerErrorOnWellKnownEndpoint() {
        String fullWellKnownUrl = getFullWellKnownUrl();
        oidcDispatcher.setOidcResponse("Server Error", 500);

        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Failed to fetch discovery document from " + fullWellKnownUrl + ". HTTP Status: 500");
    }

    @Test
    @DisplayName("Simulate IOException during WellKnown fetch by abruptly closing connection")
    void shouldThrowExceptionForConnectionErrorOnWellKnownEndpoint() {
        // Configure MockWebServer to fail the connection for the OIDC path
        mockWebServer.setDispatcher(new Dispatcher() {
            @NotNull
            @Override
            public MockResponse dispatch(@NotNull RecordedRequest request) {
                if (DEFAULT_OIDC_PATH.equals(request.getPath())) {
                    return new okhttp3.mockwebserver.MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START);
                }
                return new okhttp3.mockwebserver.MockResponse().setResponseCode(404); // Default for other paths
            }
        });

        String fullWellKnownUrl = getFullWellKnownUrl();
        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("IOException while fetching or reading from " + fullWellKnownUrl);
    }


    @Test
    void shouldThrowExceptionForMalformedJsonResponseFromWellKnownEndpoint() {
        String fullWellKnownUrl = getFullWellKnownUrl();
        oidcDispatcher.setOidcResponse("{\"issuer\":\"test\", this_is_not_json", 200);

        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Failed to parse JSON from " + fullWellKnownUrl);
    }

    @Test
    void shouldThrowExceptionForMissingIssuerField() {
        String fullWellKnownUrl = getFullWellKnownUrl();
        String oidcConfigJson = "{\"jwks_uri\":\"##JWKS_URI##\"}"; // Missing issuer

        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        oidcDispatcher.setJwksResponse(DEFAULT_JWKS_PATH, "{\"keys\":[]}", 200);

        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Required field 'issuer' not found in discovery document from " + fullWellKnownUrl);
    }

    @Test
    void shouldThrowExceptionForMissingJwksUriField() {
        String serverBaseUrl = uriBuilder.build().toString();
        String fullWellKnownUrl = getFullWellKnownUrl();
        String oidcConfigJson = String.format("{\"issuer\":\"%s\"}", serverBaseUrl); // Missing jwks_uri

        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        // No JWKS setup needed as it should fail before jwks_uri accessibility check

        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Required URL field 'jwks_uri' is missing in discovery document from " + fullWellKnownUrl);
    }

    @Test
    void shouldThrowExceptionForMalformedIssuerUrlInDocument() {
        String fullWellKnownUrl = getFullWellKnownUrl();
        String malformedIssuer = "htp:/invalid-issuer.com";
        String oidcConfigJson = String.format("{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}", malformedIssuer);

        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        oidcDispatcher.setJwksResponse(DEFAULT_JWKS_PATH, "{\"keys\":[]}", 200);

        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Issuer URL from discovery document is malformed: " + malformedIssuer);
    }

    @Test
    void shouldThrowExceptionForMalformedJwksUriUrlInDocument() {
        String serverBaseUrl = uriBuilder.build().toString();
        String fullWellKnownUrl = getFullWellKnownUrl();
        String malformedJwksUri = "htp:/invalid-jwks-uri.com";
        String oidcConfigJson = String.format("{\"issuer\":\"%s\", \"jwks_uri\":\"%s\"}", serverBaseUrl, malformedJwksUri);

        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        // No JWKS setup for accessibility needed, as it should fail on malformed URL parsing.

        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Malformed URL for field 'jwks_uri': " + malformedJwksUri);
    }

    @Test
    void shouldThrowExceptionForIssuerMismatch() {
        String fullWellKnownUrl = getFullWellKnownUrl();
        String differentIssuer = "https://different-server.com";
        String oidcConfigJson = String.format("{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}", differentIssuer);

        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        oidcDispatcher.setJwksResponse(DEFAULT_JWKS_PATH, "{\"keys\":[]}", 200);

        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Issuer validation failed. Document issuer '" + differentIssuer + "'")
            .hasMessageContaining("does not match the .well-known URL '" + fullWellKnownUrl + "'");
    }

    @Test
    void shouldSucceedWhenIssuerHasPathAndMatchesWellKnown() throws MalformedURLException {
        String serverBaseUrl = uriBuilder.build().toString(); // e.g., http://localhost:12345
        String tenantPath = "/tenant1";
        String issuerWithPath = serverBaseUrl.endsWith("/") ? serverBaseUrl + tenantPath.substring(1) : serverBaseUrl + tenantPath;
        String fullWellKnownUrlForTenant = issuerWithPath + DEFAULT_OIDC_PATH;

        String tenantOidcPath = tenantPath + DEFAULT_OIDC_PATH;
        String tenantJwksPath = tenantPath + DEFAULT_JWKS_PATH;
        String expectedJwksUriForTenant = issuerWithPath + DEFAULT_JWKS_PATH;


        String oidcConfigJson = String.format(
            "{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}", // ##JWKS_URI## will be replaced with mockServer.url(tenantJwksPath)
            issuerWithPath
        );

        // Configure dispatcher for tenant-specific paths
        oidcDispatcher.oidcPath = tenantOidcPath; // Tell dispatcher to listen on this path for OIDC
        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        oidcDispatcher.setJwksResponse(tenantJwksPath, "{\"keys\":[]}", 200);


        WellKnownHandler handler = WellKnownHandler.fromWellKnownUrl(fullWellKnownUrlForTenant);

        assertThat(handler.getWellKnownUrl().toString()).isEqualTo(fullWellKnownUrlForTenant);
        assertThat(handler.getIssuer()).isPresent().contains(new URL(issuerWithPath));
        assertThat(handler.getJwksUri()).isPresent().get().asString().isEqualTo(expectedJwksUriForTenant);
    }


    @Test
    void shouldThrowWhenIssuerHasPathButMismatchWellKnown() {
        String serverBaseUrl = uriBuilder.build().toString();
        String issuerWithTenantPath = serverBaseUrl + "tenant1"; // Issuer is specific, no trailing slash
        String actualWellKnownUrl = getFullWellKnownUrl(); // Fetched from root: http://localhost:xxxx/.well-known/...

        String oidcConfigJson = String.format(
            "{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}",
            issuerWithTenantPath
        );

        oidcDispatcher.setOidcResponse(oidcConfigJson, 200); // Served from DEFAULT_OIDC_PATH (root)
        oidcDispatcher.setJwksResponse(DEFAULT_JWKS_PATH, "{\"keys\":[]}", 200);

        assertThatThrownBy(() -> WellKnownHandler.fromWellKnownUrl(actualWellKnownUrl))
            .isInstanceOf(WellKnownDiscoveryException.class)
            .hasMessageContaining("Issuer validation failed. Document issuer '" + issuerWithTenantPath + "'")
            .hasMessageContaining("does not match the .well-known URL '" + actualWellKnownUrl + "'");
    }


    @Test
    void shouldHandleInaccessibleJwksUriGracefully() throws MalformedURLException {
        String serverBaseUrl = uriBuilder.build().toString();
        String fullWellKnownUrl = getFullWellKnownUrl();
        String expectedJwksUri = serverBaseUrl.endsWith("/") ? serverBaseUrl + DEFAULT_JWKS_PATH.substring(1) : serverBaseUrl + DEFAULT_JWKS_PATH;

        String oidcConfigJson = String.format(
            "{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}",
            serverBaseUrl
        );

        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        oidcDispatcher.setJwksResponse(DEFAULT_JWKS_PATH, "Error body for JWKS", 404); // jwks_uri is inaccessible

        WellKnownHandler handler = WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl);

        assertThat(handler.getWellKnownUrl().toString()).isEqualTo(fullWellKnownUrl);
        assertThat(handler.getIssuer()).isPresent().contains(new URL(serverBaseUrl));
        assertThat(handler.getJwksUri()).isPresent().get().asString().isEqualTo(expectedJwksUri);
    }

    @Test
    @DisplayName("Simulate IOException during JWKS accessibility check")
    void shouldHandleJwksUriConnectionErrorGracefully() throws MalformedURLException {
        String serverBaseUrl = uriBuilder.build().toString();
        String fullWellKnownUrl = getFullWellKnownUrl();
        String expectedJwksUri = serverBaseUrl.endsWith("/") ? serverBaseUrl + DEFAULT_JWKS_PATH.substring(1) : serverBaseUrl + DEFAULT_JWKS_PATH;

        String oidcConfigJson = String.format(
            "{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}",
            serverBaseUrl
        );

        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        // Configure MockWebServer to fail the connection for the JWKS path
        // We need a new dispatcher instance for this specific behavior on the JWKS path
        mockWebServer.setDispatcher(new Dispatcher() {
            @NotNull
            @Override
            public MockResponse dispatch(@NotNull RecordedRequest request) {
                if (DEFAULT_OIDC_PATH.equals(request.getPath())) {
                    // Serve the OIDC config correctly
                    String dynamicOidcBody = oidcConfigJson.replace("##JWKS_URI##", mockWebServer.url(DEFAULT_JWKS_PATH).toString());
                    return new okhttp3.mockwebserver.MockResponse().setResponseCode(200).setBody(dynamicOidcBody).setHeader("Content-Type", JSON_CONTENT_TYPE);
                } else if (DEFAULT_JWKS_PATH.equals(request.getPath())) {
                    // Fail the JWKS request
                    return new okhttp3.mockwebserver.MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START);
                }
                return new okhttp3.mockwebserver.MockResponse().setResponseCode(404);
            }
        });


        WellKnownHandler handler = WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl);

        assertThat(handler.getWellKnownUrl().toString()).isEqualTo(fullWellKnownUrl);
        assertThat(handler.getIssuer()).isPresent().contains(new URL(serverBaseUrl));
        assertThat(handler.getJwksUri()).isPresent().get().asString().isEqualTo(expectedJwksUri);
        // The checkAccessibility logs a warning but doesn't prevent handler creation or jwks_uri retrieval
    }


    @Test
    void allGettersShouldReturnCorrectValues() throws MalformedURLException {
        String serverBaseUrl = uriBuilder.build().toString();
        String fullWellKnownUrl = getFullWellKnownUrl();
        String expectedJwksUri = serverBaseUrl.endsWith("/") ? serverBaseUrl + DEFAULT_JWKS_PATH.substring(1) : serverBaseUrl + DEFAULT_JWKS_PATH;
        String authorizationEndpoint = serverBaseUrl + "auth";
        String tokenEndpoint = serverBaseUrl + "token";
        String userinfoEndpoint = serverBaseUrl + "userinfo";

        String oidcConfigJson = String.format(
            "{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\", \"authorization_endpoint\":\"%s\", \"token_endpoint\":\"%s\", \"userinfo_endpoint\":\"%s\"}",
            serverBaseUrl, authorizationEndpoint, tokenEndpoint, userinfoEndpoint
        );
        oidcDispatcher.setOidcResponse(oidcConfigJson, 200);
        oidcDispatcher.setJwksResponse(DEFAULT_JWKS_PATH, "{\"keys\":[]}", 200);
        WellKnownHandler handler = WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl);

        assertThat(handler.getWellKnownUrl()).isEqualTo(new URL(fullWellKnownUrl));
        assertThat(handler.getIssuer()).isEqualTo(Optional.of(new URL(serverBaseUrl)));
        assertThat(handler.getJwksUri()).isEqualTo(Optional.of(new URL(expectedJwksUri)));
        assertThat(handler.getAuthorizationEndpoint()).isEqualTo(Optional.of(new URL(authorizationEndpoint)));
        assertThat(handler.getTokenEndpoint()).isEqualTo(Optional.of(new URL(tokenEndpoint)));
        assertThat(handler.getUserinfoEndpoint()).isEqualTo(Optional.of(new URL(userinfoEndpoint)));

        // Test with missing optional fields
        oidcDispatcher.reset(); // Clear previous stubs
        String minimalOidcConfigJson = String.format("{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}", serverBaseUrl);
        oidcDispatcher.setOidcResponse(minimalOidcConfigJson, 200);
        oidcDispatcher.setJwksResponse(DEFAULT_JWKS_PATH, "{\"keys\":[]}", 200);
        handler = WellKnownHandler.fromWellKnownUrl(fullWellKnownUrl);

        assertThat(handler.getWellKnownUrl()).isEqualTo(new URL(fullWellKnownUrl));
        assertThat(handler.getIssuer()).isEqualTo(Optional.of(new URL(serverBaseUrl)));
        assertThat(handler.getJwksUri()).isEqualTo(Optional.of(new URL(expectedJwksUri)));
        assertThat(handler.getAuthorizationEndpoint()).isEmpty();
        assertThat(handler.getTokenEndpoint()).isEmpty();
        assertThat(handler.getUserinfoEndpoint()).isEmpty();
    }
}
