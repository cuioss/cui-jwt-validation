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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.wellKnown.WellKnownHandler;
import de.cuioss.test.keycloakit.KeycloakITBase;
import de.cuioss.test.keycloakit.TestRealm;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.Splitter;
import io.restassured.RestAssured;
import io.restassured.config.SSLConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.net.URL;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Tests Token integration with Keycloak")
public class TokenKeycloakITTest extends KeycloakITBase {

    public static final String SCOPES = "openid email profile";
    public static final List<String> SCOPES_AS_LIST = Splitter.on(" ").splitToList(SCOPES);
    private static final CuiLogger LOGGER = new CuiLogger(TokenKeycloakITTest.class);

    private TokenValidator preConfiguredFactory; // Renamed from 'factory' to avoid confusion
    private String authServerUrlString; // To cache the auth server URL
    private static SSLConfig restAssuredSslConfig;
    private static SSLContext trustAllSslContext;

    /**
     * Creates an SSLContext that trusts all certificates.
     * WARNING: This should only be used for testing purposes, never in production!
     *
     * @return an SSLContext that trusts all certificates
     * @throws Exception if an error occurs
     */
    private static SSLContext createTrustAllSSLContext() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    // Trust all client certificates
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    // Trust all server certificates
                }
            }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, null); // Using null for KeyManager and SecureRandom for simplicity in trust-all
        return sslContext;
    }

    @BeforeAll
    static void globalSetup() throws Exception {
        // Configure RestAssured to use the keystore used / provided by testcontainers-keycloak
        // This is needed for RestAssured to trust the Keycloak instance's SSL certificate.
        restAssuredSslConfig = SSLConfig.sslConfig().trustStore(TestRealm.ProvidedKeyStore.KEYSTORE_PATH, TestRealm.ProvidedKeyStore.PASSWORD);
        RestAssured.config = RestAssured.config().sslConfig(restAssuredSslConfig);

        // Create a trust-all SSLContext for HttpJwksLoader and WellKnownHandler if needed.
        // WellKnownHandler uses default JVM context. If Keycloak uses HTTPS and its cert isn't in default JVM truststore,
        // direct calls from WellKnownHandler might fail.
        // However, testcontainers-keycloak often uses a cert trusted by the host or maps to HTTP.
        // For HttpJwksLoader, we explicitly pass this context.
        trustAllSslContext = createTrustAllSSLContext();

        // Log the keystore path and password for debugging
        LOGGER.debug(() -> "KEYSTORE_PATH: " + TestRealm.ProvidedKeyStore.KEYSTORE_PATH);
        LOGGER.debug(() -> "PASSWORD: " + TestRealm.ProvidedKeyStore.PASSWORD);
    }


    @BeforeEach
    void setUp() {
        String issuerString = getIssuer(); // This is String as per KeycloakITBase
        if (issuerString == null) {
            throw new IllegalStateException("getIssuer() returned null, cannot derive authServerUrlString");
        }
        int realmsIndex = issuerString.indexOf("/realms/");
        if (realmsIndex != -1) {
            this.authServerUrlString = issuerString.substring(0, realmsIndex);
        } else {
            // Fallback or error if "/realms/" is not found.
            // This indicates an unexpected issuer format from KeycloakITBase.
            // For now, assign the full issuer string to potentially highlight the issue later,
            // or throw an exception.
            LOGGER.warn("'/realms/' not found in issuer string '{}', authServerUrlString may be incorrect.", issuerString);
            this.authServerUrlString = issuerString;
        }
        LOGGER.info("Derived authServerUrlString: {}", this.authServerUrlString);


        // Create a JwksLoader with the SSLContext that trusts Keycloak's certificate
        HttpJwksLoaderConfig httpJwksConfig = HttpJwksLoaderConfig.builder()
            .jwksUrl(getJWKSUrl()) // Direct JWKS URL from Keycloak container
            .refreshIntervalSeconds(100)
            .sslContext(trustAllSslContext) // Use the globally created trust-all context
            .build();

        // Create an IssuerConfig
        IssuerConfig issuerConfig = IssuerConfig.builder()
            .issuer(getIssuer()) // Direct Issuer URL from Keycloak container
            .expectedAudience("test-user-client") // Corrected method name
            .httpJwksLoaderConfig(httpJwksConfig)
            .build();

        // Create the validation factory
        preConfiguredFactory = new TokenValidator(issuerConfig);
    }

    private String requestToken(Map<String, String> parameter, String tokenType) {
        String tokenString = given().config(RestAssured.config().sslConfig(restAssuredSslConfig)) // Ensure RestAssured uses the SSL config
            .contentType("application/x-www-form-urlencoded")
            .formParams(parameter)
            .post(getTokenUrl()).then().assertThat().statusCode(200)
            .extract().path(tokenType);
        LOGGER.info(() -> "Received %s: %s".formatted(tokenType, tokenString));
        return tokenString;
    }

    @Nested
    @DisplayName("Access Token Tests")
    class AccessTokenTests {
        @Test
        @DisplayName("Should handle valid access token")
        void shouldHandleValidAccessToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ACCESS);
            var accessToken = preConfiguredFactory.createAccessToken(tokenString);

            assertFalse(accessToken.isExpired(), "Token should not be expired");
            // Check if all scopes are present in the token
            List<String> tokenScopes = accessToken.getScopes();
            assertTrue(tokenScopes.containsAll(SCOPES_AS_LIST), "Token should provide requested scopes");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), accessToken.getEmail().orElse(""), "Email should match test user");
            assertEquals(TokenType.ACCESS_TOKEN, accessToken.getTokenType(), "Token type should be ACCESS_TOKEN");
            assertTrue(accessToken.getAudience().map(list -> list.contains("test-user-client")).orElse(false), "Audience should contain public client_id");
        }
    }

    @Nested
    @DisplayName("ID Token Tests")
    class IdTokenTests {
        @Test
        @DisplayName("Should handle valid ID-Token")
        void shouldHandleValidIdToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ID_TOKEN);
            var idToken = preConfiguredFactory.createIdToken(tokenString);

            assertFalse(idToken.isExpired(), "Token should not be expired");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), idToken.getEmail().orElse(""), "Email should match test user");
            assertEquals(TokenType.ID_TOKEN, idToken.getTokenType(), "Token type should be ID_TOKEN");
            // Corrected: IdTokenContent.getAudience() returns List<String>, not Optional<List<String>>
            assertTrue(idToken.getAudience().contains("test-user-client"), "Audience should contain public client_id");
        }
    }

    @Nested
    @DisplayName("Refresh Token Tests")
    class RefreshTokenTests {
        @Test
        @DisplayName("Should handle valid Refresh-Token")
        void shouldHandleValidRefreshToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.REFRESH);
            var refreshToken = preConfiguredFactory.createRefreshToken(tokenString);
            assertNotNull(refreshToken.getRawToken(), "Token string should not be null");
            assertEquals(TokenType.REFRESH_TOKEN, refreshToken.getTokenType(), "Token type should be REFRESH_TOKEN");
            assertFalse(refreshToken.getClaims().isEmpty());
        }
    }

    @Nested
    @DisplayName("WellKnown Discovery Validation Tests")
    class WellKnownDiscoveryValidationTests {
        // Removed setUpNested and authServerUrlForTest field

        @Test
        @DisplayName("Should validate Keycloak token using Well-Known discovery")
        void shouldValidateKeycloakTokenUsingWellKnownDiscovery() throws Exception {
            // 1. Get Keycloak's well-known URI
            // Assuming getAuthServerUrl() returns something like "https://localhost:port/auth"
            // and realm is "cui-test"
            String wellKnownUrlString = TokenKeycloakITTest.this.authServerUrlString + "/realms/" + TestRealm.REALM_NAME + "/.well-known/openid-configuration";
            LOGGER.info("Using Well-Known URL: " + wellKnownUrlString);

            // 2. Perform OIDC Discovery
            // WellKnownHandler uses default JVM SSL context. If Keycloak runs on HTTPS with self-signed cert,
            // this might need a custom SSLSocketFactory or trust store setup for the JVM,
            // or ensure Keycloak is accessible via HTTP for this test.
            // Testcontainers usually handles this by exposing on HTTP or using a trusted cert.
            WellKnownHandler wellKnownHandler = WellKnownHandler.fromWellKnownUrl(wellKnownUrlString);
            assertTrue(wellKnownHandler.getJwksUri().isPresent(), "JWKS URI should be present in well-known config");
            assertTrue(wellKnownHandler.getIssuer().isPresent(), "Issuer should be present in well-known config");
            URL keycloakIssuerUrl = wellKnownHandler.getIssuer().get();

            // 3. Configure HttpJwksLoaderConfig using WellKnownHandler
            HttpJwksLoaderConfig jwksConfig = HttpJwksLoaderConfig.builder()
                .wellKnown(wellKnownHandler)
                .sslContext(trustAllSslContext) // Use the trust-all context for JWKS loading
                .refreshIntervalSeconds(10) // Short refresh for test
                .build();

            // 4. Configure IssuerConfig and TokenValidator
            IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(keycloakIssuerUrl.toString()) // Use issuer from discovery
                .expectedAudience("test-user-client") // Corrected method name
                .httpJwksLoaderConfig(jwksConfig)
                .build();
            TokenValidator validator = new TokenValidator(issuerConfig);

            // 5. Obtain a token from Keycloak
            String rawToken = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ACCESS);

            // 6. Validate the token
            var accessToken = validator.createAccessToken(rawToken);

            // 7. Assertions
            assertNotNull(accessToken, "Validated token should not be null");
            assertFalse(accessToken.isExpired(), "Token should not be expired");
            assertEquals(keycloakIssuerUrl.toString(), accessToken.getIssuer(), "Issuer should match discovery"); // getIssuer() returns String
            assertTrue(accessToken.getAudience().map(list -> list.contains("test-user-client")).orElse(false), "Audience should match");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), accessToken.getEmail().orElse(""), "Email should match test user");
            assertEquals(TokenType.ACCESS_TOKEN, accessToken.getTokenType(), "Token type should be ACCESS_TOKEN");
        }

        @Test
        @DisplayName("Should fail validation if expected issuer is incorrect (via Well-Known discovery setup)")
        void shouldFailValidationWithIncorrectExpectedIssuerViaWellKnown() throws Exception {
            String wellKnownUrlString = TokenKeycloakITTest.this.authServerUrlString + "/realms/" + TestRealm.REALM_NAME + "/.well-known/openid-configuration";
            WellKnownHandler wellKnownHandler = WellKnownHandler.fromWellKnownUrl(wellKnownUrlString);
            assertTrue(wellKnownHandler.getIssuer().isPresent(), "Issuer should be present in well-known config");

            HttpJwksLoaderConfig jwksConfig = HttpJwksLoaderConfig.builder()
                .wellKnown(wellKnownHandler)
                .sslContext(trustAllSslContext)
                .build();

            String incorrectIssuer = "https://incorrect-issuer.com/auth/realms/cui-test";
            IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(incorrectIssuer) // Manually set incorrect issuer
                .expectedAudience("test-user-client") // Corrected method name
                .httpJwksLoaderConfig(jwksConfig)
                .build();
            TokenValidator validator = new TokenValidator(issuerConfig);

            String rawToken = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ACCESS);

            // Assert that validation fails with TokenValidationException (or a more specific one if applicable)
            assertThrows(TokenValidationException.class, () -> {
                validator.createAccessToken(rawToken);
            }, "Validation should fail due to issuer mismatch");
        }
    }
}
