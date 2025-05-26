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

import de.cuioss.jwt.validation.security.SecureSSLContextProvider;
import de.cuioss.jwt.validation.wellKnown.WellKnownHandler;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.NoSuchAlgorithmException; // Added import
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals; // Specific import for this one
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;


@EnableTestLogger
@DisplayName("Tests HttpJwksLoaderConfig")
@SuppressWarnings({"java:S5778", "DataFlowIssue"})
// owolff: Suppressing because for a builder this is not a problem
// S5778: Assertions should be complete (sonar) - will be addressed if necessary by other changes.
// DataFlowIssue: For null checks on builder methods.
class HttpJwksLoaderConfigTest {

    private static final String VALID_JWKS_URL_STRING = "https://example.com/.well-known/jwks.json";
    private static final URI VALID_JWKS_URI;

    static {
        try {
            VALID_JWKS_URI = new URI(VALID_JWKS_URL_STRING);
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final int REFRESH_INTERVAL = 60;
    private static final String JSON_CONTENT_TYPE = "application/json;charset=utf-8";

    // For testing WellKnownHandler integration with MockWebServer
    protected MockWebServer mockWebServer;
    protected URIBuilder uriBuilder;
    private TestOidcDispatcher testOidcDispatcher; // Dispatcher for MockWebServer

    private static final String OIDC_TEST_PATH = "/test/.well-known/openid-configuration";
    private static final String JWKS_TEST_PATH = "/test/jwks.json";

    // Inner Dispatcher class for MockWebServer
    static class TestOidcDispatcher extends Dispatcher {
        private String oidcPath = OIDC_TEST_PATH;
        private String jwksPath = JWKS_TEST_PATH;
        private String oidcBody;
        private String jwksBody;
        private int oidcStatusCode = 200;
        private int jwksStatusCode = 200;
        private boolean oidcConfigured = false;
        private boolean jwksConfigured = false;
        private final MockWebServer mockWebServerInstance;

        public TestOidcDispatcher(MockWebServer mockWebServerInstance) {
            this.mockWebServerInstance = mockWebServerInstance;
        }

        public void setOidcResponse(String path, String body, int code) {
            this.oidcPath = path;
            this.oidcBody = body;
            this.oidcStatusCode = code;
            this.oidcConfigured = true;
        }

        public void setJwksResponse(String path, String body, int code) {
            this.jwksPath = path;
            this.jwksBody = body;
            this.jwksStatusCode = code;
            this.jwksConfigured = true;
        }

        @NotNull
        @Override
        public MockResponse dispatch(@NotNull RecordedRequest request) {
            String requestPath = request.getRequestUrl().encodedPath();
            if (oidcPath.equals(requestPath) && oidcConfigured) {
                String dynamicOidcBody = oidcBody;
                if (oidcBody != null && oidcBody.contains("##JWKS_URI##")) {
                    dynamicOidcBody = oidcBody.replace("##JWKS_URI##", mockWebServerInstance.url(jwksPath).toString());
                }
                return new okhttp3.mockwebserver.MockResponse().setResponseCode(oidcStatusCode).setBody(dynamicOidcBody).setHeader("Content-Type", JSON_CONTENT_TYPE);
            } else if (jwksPath.equals(requestPath) && jwksConfigured) {
                okhttp3.mockwebserver.MockResponse resp = new okhttp3.mockwebserver.MockResponse().setResponseCode(jwksStatusCode).setHeader("Content-Type", JSON_CONTENT_TYPE);
                if ("HEAD".equalsIgnoreCase(request.getMethod())) {
                    resp.setBody(""); // No body for HEAD
                } else {
                    resp.setBody(jwksBody);
                }
                return resp;
            }
            return new okhttp3.mockwebserver.MockResponse().setResponseCode(404).setBody("Not Found for path: " + requestPath);
        }

        public void reset() {
            oidcConfigured = false;
            jwksConfigured = false;
            oidcBody = null;
            jwksBody = null;
            oidcStatusCode = 200;
            jwksStatusCode = 200;
            oidcPath = OIDC_TEST_PATH; // Reset to default test paths
            jwksPath = JWKS_TEST_PATH;
        }
    }

    @BeforeEach
    void initializeMockWebServer(MockWebServer mockWebServer, URIBuilder uriBuilder) {
        this.mockWebServer = mockWebServer;
        this.uriBuilder = uriBuilder;
        this.testOidcDispatcher = new TestOidcDispatcher(this.mockWebServer);
        this.mockWebServer.setDispatcher(this.testOidcDispatcher);
        this.testOidcDispatcher.reset();
    }

    @Test
    @DisplayName("Should create config with default values using jwksUrl")
    void shouldCreateConfigWithDefaultValues() {
        // Given
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
            .jwksUrl(VALID_JWKS_URL_STRING)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .build();

        // Then
        assertThat(config.getJwksUri()).isEqualTo(VALID_JWKS_URI);
        assertThat(config.getRefreshIntervalSeconds()).isEqualTo(REFRESH_INTERVAL);
        assertThat(config.getSslContext()).isNotNull();
        assertThat(config.getMaxCacheSize()).isEqualTo(100); // Default value
        assertThat(config.getAdaptiveWindowSize()).isEqualTo(10); // Default value
        assertThat(config.getRequestTimeoutSeconds()).isEqualTo(10); // Default value
        assertThat(config.getBackgroundRefreshPercentage()).isEqualTo(80); // Default value
    }

    @Test
    @DisplayName("Should create config with custom values using jwksUri")
    void shouldCreateConfigWithCustomValues() throws NoSuchAlgorithmException {
        // Given
        SSLContext sslContext = SSLContext.getDefault();
        int maxCacheSize = 200;
        int adaptiveWindowSize = 20;
        int requestTimeoutSeconds = 15;
        int backgroundRefreshPercentage = 70;

        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
            .jwksUri(VALID_JWKS_URI)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .sslContext(sslContext)
            .maxCacheSize(maxCacheSize)
            .adaptiveWindowSize(adaptiveWindowSize)
            .requestTimeoutSeconds(requestTimeoutSeconds)
            .backgroundRefreshPercentage(backgroundRefreshPercentage)
            .build();

        // Then
        assertThat(config.getJwksUri()).isEqualTo(VALID_JWKS_URI);
        assertThat(config.getRefreshIntervalSeconds()).isEqualTo(REFRESH_INTERVAL);
        assertThat(config.getSslContext()).isNotNull();
        assertThat(config.getMaxCacheSize()).isEqualTo(maxCacheSize);
        assertThat(config.getAdaptiveWindowSize()).isEqualTo(adaptiveWindowSize);
        assertThat(config.getRequestTimeoutSeconds()).isEqualTo(requestTimeoutSeconds);
        assertThat(config.getBackgroundRefreshPercentage()).isEqualTo(backgroundRefreshPercentage);
    }

    @Test
    @DisplayName("Should handle jwksUrl without scheme, prepending https")
    void shouldHandleUrlWithoutScheme() {
        // Given
        String urlWithoutScheme = "example.com/jwks.json";
        URI expectedUri = URI.create("https://" + urlWithoutScheme); // Builder prepends https

        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
            .jwksUrl(urlWithoutScheme)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .build();

        // Then
        assertThat(config.getJwksUri()).isEqualTo(expectedUri);
    }

    @Test
    @DisplayName("Should throw for invalid jwksUrl string")
    void shouldThrowForInvalidUrlString() {
        // Given
        String invalidUrl = "invalid url with spaces";

        // When / Then
        assertThatThrownBy(() -> HttpJwksLoaderConfig.builder()
            .jwksUrl(invalidUrl)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Invalid JWKS URL string: " + invalidUrl);
    }


    @Test
    @DisplayName("Should use SecureSSLContextProvider if provided")
    void shouldUseSecureSSLContextProvider() {
        // Given
        SecureSSLContextProvider secureProvider = new SecureSSLContextProvider();

        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
            .jwksUri(VALID_JWKS_URI)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .tlsVersions(secureProvider)
            .build();

        // Then
        assertThat(config.getSslContext()).isNotNull();
    }

    @Test
    @DisplayName("Should throw exception for negative refresh interval")
    void shouldThrowExceptionForNegativeRefreshInterval() {
        // When/Then
        assertThatThrownBy(() -> HttpJwksLoaderConfig.builder()
            .jwksUri(VALID_JWKS_URI)
            .refreshIntervalSeconds(-1)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Refresh interval must not be negative");
    }

    @Test
    @DisplayName("Should throw exception for negative max cache size")
    void shouldThrowExceptionForNegativeMaxCacheSize() {
        // When/Then
        assertThatThrownBy(() -> HttpJwksLoaderConfig.builder()
            .jwksUri(VALID_JWKS_URI)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .maxCacheSize(-1)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Max cache size must be positive");
    }

    @Test
    @DisplayName("Should throw exception for negative adaptive window size")
    void shouldThrowExceptionForNegativeAdaptiveWindowSize() {
        // When/Then
        assertThatThrownBy(() -> HttpJwksLoaderConfig.builder()
            .jwksUri(VALID_JWKS_URI)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .adaptiveWindowSize(-1)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Adaptive window size must be positive");
    }

    @Test
    @DisplayName("Should throw exception for negative request timeout")
    void shouldThrowExceptionForNegativeRequestTimeout() {
        // When/Then
        assertThatThrownBy(() -> HttpJwksLoaderConfig.builder()
            .jwksUri(VALID_JWKS_URI)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .requestTimeoutSeconds(-1)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Request timeout must be positive");
    }

    @Test
    @DisplayName("Should throw exception for negative background refresh percentage")
    void shouldThrowExceptionForNegativeBackgroundRefreshPercentage() {
        // When/Then
        assertThatThrownBy(() -> HttpJwksLoaderConfig.builder()
            .jwksUri(VALID_JWKS_URI)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .backgroundRefreshPercentage(-1)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Background refresh percentage must be between 1 and 100");
    }

    @Test
    @DisplayName("Should throw exception for zero background refresh percentage")
    void shouldThrowExceptionForZeroBackgroundRefreshPercentage() {
        // When/Then
        assertThatThrownBy(() -> HttpJwksLoaderConfig.builder()
            .jwksUri(VALID_JWKS_URI)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .backgroundRefreshPercentage(0)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Background refresh percentage must be between 1 and 100");
    }

    @Test
    @DisplayName("Should throw exception for too high background refresh percentage")
    void shouldThrowExceptionForTooHighBackgroundRefreshPercentage() {
        // When/Then
        assertThatThrownBy(() -> HttpJwksLoaderConfig.builder()
            .jwksUri(VALID_JWKS_URI)
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .backgroundRefreshPercentage(101)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Background refresh percentage must be between 1 and 100");
    }

    @Test
    @DisplayName("Should throw exception for missing JWKS URI source")
    void shouldThrowExceptionForMissingJwksUriSource() {
        // When/Then
        assertThatThrownBy(() -> HttpJwksLoaderConfig.builder()
            .refreshIntervalSeconds(REFRESH_INTERVAL)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("JWKS URI must be configured. Use jwksUri(), jwksUrl(), or wellKnown().");
    }

    @Nested
    @DisplayName("WellKnownHandler Configuration Tests")
    class WellKnownHandlerConfigTests {

        private String mockServerBaseUrl;
        private String oidcDiscoveryUrl; // Full URL for OIDC discovery
        // JWKS URI will be dynamic based on mock server

        @BeforeEach
        void setUpDispatcherUrls() {
            mockServerBaseUrl = uriBuilder.build().toString();
            // Ensure no trailing slash for consistency if uriBuilder.build() adds one.
            if (mockServerBaseUrl.endsWith("/")) {
                mockServerBaseUrl = mockServerBaseUrl.substring(0, mockServerBaseUrl.length() - 1);
            }
            oidcDiscoveryUrl = mockServerBaseUrl + OIDC_TEST_PATH;
        }

        private WellKnownHandler createHandlerWithJwksUri(String oidcPath, String jwksPathInOidcDoc, String actualJwksPathForServer, String issuerUrlInOidcDoc) {
            // The jwks_uri in the OIDC doc will be dynamically replaced by the dispatcher
            String oidcConfigJson = String.format("{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}",
                issuerUrlInOidcDoc);

            testOidcDispatcher.setOidcResponse(oidcPath, oidcConfigJson, 200);
            testOidcDispatcher.setJwksResponse(actualJwksPathForServer, "{\"keys\":[]}", 200); // Path for JWKS server

            return WellKnownHandler.fromWellKnownUrl(oidcDiscoveryUrl);
        }

        private WellKnownHandler createHandlerWithoutJwksUri(String oidcPath, String issuerUrlInOidcDoc) {
            String oidcConfigJson = String.format("{\"issuer\":\"%s\"}", issuerUrlInOidcDoc);
            testOidcDispatcher.setOidcResponse(oidcPath, oidcConfigJson, 200);
            // No JWKS response needed as WellKnownHandler should fail before accessing it
            return WellKnownHandler.fromWellKnownUrl(oidcDiscoveryUrl);
        }

        @Test
        @DisplayName("Should configure via wellKnown() successfully")
        void shouldConfigureViaWellKnownHandler() throws MalformedURLException, URISyntaxException {
            WellKnownHandler handler = createHandlerWithJwksUri(OIDC_TEST_PATH, JWKS_TEST_PATH, JWKS_TEST_PATH, mockServerBaseUrl);
            String expectedJwksUriString = mockWebServer.url(JWKS_TEST_PATH).toString();

            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .wellKnown(handler)
                .build();

            assertThat(config.getJwksUri()).isEqualTo(new URI(expectedJwksUriString));
        }

        @Test
        @DisplayName("Should throw from wellKnown() when handler is null")
        void shouldThrowFromWellKnownWhenHandlerIsNull() {
            assertThatThrownBy(() -> HttpJwksLoaderConfig.builder().wellKnown(null))
                .isInstanceOf(NullPointerException.class) // Due to @NonNull on the parameter
                .hasMessageContaining("wellKnownHandler");
        }

        @Test
        @DisplayName("Should throw from wellKnown() when handler lacks jwks_uri")
        void shouldThrowFromWellKnownWhenHandlerLacksJwksUri() {
            WellKnownHandler handlerWithoutJwks = createHandlerWithoutJwksUri(OIDC_TEST_PATH, mockServerBaseUrl);

            assertThatThrownBy(() -> HttpJwksLoaderConfig.builder().wellKnown(handlerWithoutJwks).build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("WellKnownHandler (issuer: " + mockServerBaseUrl + ") must provide a jwks_uri.");
        }

        @Test
        @DisplayName("Should throw from wellKnown() when jwks_uri in handler is malformed")
        void shouldThrowFromWellKnownWhenJwksUriInHandlerIsMalformed() {
            String malformedJwksUriInDoc = "htp:/\\this is not a valid uri";
            String oidcConfigJson = String.format("{\"issuer\":\"%s\", \"jwks_uri\":\"%s\"}",
                mockServerBaseUrl, malformedJwksUriInDoc);

            testOidcDispatcher.setOidcResponse(OIDC_TEST_PATH, oidcConfigJson, 200);
            // No need to mock JWKS accessibility for a malformed URI

            WellKnownHandler handler = WellKnownHandler.fromWellKnownUrl(oidcDiscoveryUrl);

            assertThatThrownBy(() -> HttpJwksLoaderConfig.builder().wellKnown(handler).build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid jwks_uri syntax from WellKnownHandler: " + malformedJwksUriInDoc);
        }
    }

    @Nested
    @DisplayName("Builder Precedence Tests")
    class BuilderPrecedenceTests {
        private WellKnownHandler validHandler;
        private URI otherUri;
        private String otherUrlString;
        private String mockServerJwksUriString;

        @BeforeEach
        void setUp() throws URISyntaxException {
            String mockServerBase = uriBuilder.build().toString();
            if (mockServerBase.endsWith("/")) {
                mockServerBase = mockServerBase.substring(0, mockServerBase.length() - 1);
            }
            String oidcDiscUrl = mockServerBase + OIDC_TEST_PATH;
            mockServerJwksUriString = mockServerBase + JWKS_TEST_PATH;


            String oidcConfigJson = String.format("{\"issuer\":\"%s\", \"jwks_uri\":\"##JWKS_URI##\"}", mockServerBase);
            testOidcDispatcher.setOidcResponse(OIDC_TEST_PATH, oidcConfigJson, 200);
            testOidcDispatcher.setJwksResponse(JWKS_TEST_PATH, "{\"keys\":[]}", 200);
            validHandler = WellKnownHandler.fromWellKnownUrl(oidcDiscUrl);

            otherUri = new URI("https://example.org/other-jwks.json");
            otherUrlString = "https://example.net/another-jwks.json";
        }

        @Test
        @DisplayName("wellKnown() then jwksUri() -> jwksUri() wins")
        void wellKnownThenJwksUri() {
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .wellKnown(validHandler)
                .jwksUri(otherUri)
                .build();
            assertThat(config.getJwksUri()).isEqualTo(otherUri);
        }

        @Test
        @DisplayName("jwksUri() then wellKnown() -> wellKnown() wins")
        void jwksUriThenWellKnown() {
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUri(otherUri)
                .wellKnown(validHandler)
                .build();
            assertThat(config.getJwksUri().toString()).isEqualTo(mockServerJwksUriString);
        }

        @Test
        @DisplayName("wellKnown() then jwksUrl() -> jwksUrl() wins")
        void wellKnownThenJwksUrl() throws URISyntaxException {
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .wellKnown(validHandler)
                .jwksUrl(otherUrlString)
                .build();
            assertThat(config.getJwksUri()).isEqualTo(new URI(otherUrlString));
        }

        @Test
        @DisplayName("jwksUrl() then wellKnown() -> wellKnown() wins")
        void jwksUrlThenWellKnown() {
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(otherUrlString)
                .wellKnown(validHandler)
                .build();
            assertThat(config.getJwksUri().toString()).isEqualTo(mockServerJwksUriString);
        }

        @Test
        @DisplayName("jwksUri() then jwksUrl() -> jwksUrl() wins if jwksUri was cleared by jwksUrl(null) - actually jwksUrl processes")
        void jwksUriThenJwksUrl() throws URISyntaxException {
             HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder builder = HttpJwksLoaderConfig.builder()
                .jwksUri(otherUri); // otherUri is set

            // Now call jwksUrl, which should clear jwksUri internally and use jwksUrl for processing
            builder.jwksUrl(otherUrlString);
            HttpJwksLoaderConfig config = builder.build();

            assertThat(config.getJwksUri()).isEqualTo(new URI(otherUrlString));
        }


        @Test
        @DisplayName("jwksUrl() then jwksUri() -> jwksUri() wins")
        void jwksUrlThenJwksUri() {
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(otherUrlString)
                .jwksUri(otherUri)
                .build();
            assertThat(config.getJwksUri()).isEqualTo(otherUri);
        }
    }
}
