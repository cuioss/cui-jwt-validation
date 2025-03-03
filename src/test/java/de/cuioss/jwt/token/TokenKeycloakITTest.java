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
package de.cuioss.jwt.token;

import de.cuioss.test.keycloakit.KeycloakITBase;
import de.cuioss.test.keycloakit.TestRealm;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.Splitter;
import io.restassured.RestAssured;
import io.restassured.config.SSLConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Tests Token integration with Keycloak")
public class TokenKeycloakITTest extends KeycloakITBase {

    public static final String SCOPES = "openid email profile";
    public static final List<String> SCOPES_AS_LIST = Splitter.on(" ").splitToList(SCOPES);
    private static final CuiLogger LOGGER = new CuiLogger(TokenKeycloakITTest.class);

    private JwksAwareTokenParser parser;
    private TokenFactory factory;

    @BeforeEach
    void setUp() {
        // Configure RestAssured to use the keystore used / provided by testcontainers-keycloak
        RestAssured.config = RestAssured.config().sslConfig(
                SSLConfig.sslConfig().trustStore(TestRealm.ProvidedKeyStore.KEYSTORE_PATH, TestRealm.ProvidedKeyStore.PASSWORD)
        );

        parser = JwksAwareTokenParser.builder()
                .jwksEndpoint(getJWKSUrl())
                .jwksRefreshIntervall(100)
                .jwksIssuer(getIssuer())
                .tTlsCertificatePath(TestRealm.ProvidedKeyStore.PUBLIC_CERT)
                .build();
        factory = TokenFactory.of(parser);
    }

    @Nested
    @DisplayName("Access Token Tests")
    class AccessTokenTests {
        @Test
        @DisplayName("Should handle valid access token")
        void shouldHandleValidAccessToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ACCESS);
            var retrievedAccessToken = factory.createAccessToken(tokenString);

            assertTrue(retrievedAccessToken.isPresent(), "Access token should be present");
            var accessToken = retrievedAccessToken.get();

            assertFalse(accessToken.isExpired(), "Token should not be expired");
            assertTrue(accessToken.providesScopes(SCOPES_AS_LIST), "Token should provide requested scopes");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), accessToken.getEmail().get(), "Email should match test user");
            assertEquals(TokenType.ACCESS_TOKEN, accessToken.getType(), "Token type should be ACCESS_TOKEN");
        }
    }

    @Nested
    @DisplayName("ID Token Tests")
    class IdTokenTests {
        @Test
        @DisplayName("Should handle valid ID token")
        void shouldHandleValidIdToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ID_TOKEN);
            var idToken = factory.createIdToken(tokenString);

            assertTrue(idToken.isPresent(), "ID token should be present");
            assertFalse(idToken.get().isExpired(), "Token should not be expired");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), idToken.get().getEmail().get(), "Email should match test user");
            assertEquals(TokenType.ID_TOKEN, idToken.get().getType(), "Token type should be ID_TOKEN");
        }
    }

    @Nested
    @DisplayName("Refresh Token Tests")
    class RefreshTokenTests {
        @Test
        @DisplayName("Should handle valid refresh token")
        void shouldHandleValidRefreshToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.REFRESH);
            var refreshToken = ParsedRefreshToken.fromTokenString(tokenString);

            assertFalse(refreshToken.isEmpty(), "Refresh token should be present");
            assertNotNull(refreshToken.getTokenString(), "Token string should not be null");
            assertEquals(TokenType.REFRESH_TOKEN, refreshToken.getType(), "Token type should be REFRESH_TOKEN");
        }
    }

    private String requestToken(Map<String, String> parameter, String tokenType) {
        String tokenString = given().contentType("application/x-www-form-urlencoded")
                .formParams(parameter)
                .post(getTokenUrl()).then().assertThat().statusCode(200)
                .extract().path(tokenType);
        LOGGER.info(() -> "Received %s: %s".formatted(tokenType, tokenString));
        return tokenString;
    }
}
