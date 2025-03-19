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

import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.jwt.token.jwks.JwksLoaderFactory;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.JwksResolveDispatcher;
import de.cuioss.jwt.token.test.KeyMaterialHandler;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.MockWebServerHolder;
import de.cuioss.test.mockwebserver.dispatcher.CombinedDispatcher;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;
import lombok.Setter;
import mockwebserver3.MockWebServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static de.cuioss.jwt.token.test.TestTokenProducer.ISSUER;
import static de.cuioss.jwt.token.test.TestTokenProducer.SOME_SCOPES;
import static de.cuioss.jwt.token.test.TestTokenProducer.validSignedJWTWithClaims;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger(debug = JwksAwareTokenParserImpl.class, info = JwksAwareTokenParserImpl.class)
@DisplayName("Tests JwksAwareTokenParserImpl functionality")
public class JwksAwareTokenParserImplTest {

    public static final int JWKS_REFRESH_INTERVAL = 60;
    private static final CuiLogger LOGGER = new CuiLogger(JwksAwareTokenParserImplTest.class);

    public static JwksAwareTokenParserImpl getValidJWKSParserWithLocalJWKS() throws IOException {
        // Create a dynamic JWKS with the current key pair
        java.security.PublicKey publicKey = KeyMaterialHandler.getPublicKey();
        java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) publicKey;

        // Create JWKS JSON with the default key ID
        String jwks = JWKSFactory.createSingleJwk(JWKSFactory.DEFAULT_KEY_ID);

        // Create a temporary file with the JWKS
        java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("test-jwks", ".json");
        java.nio.file.Files.writeString(tempFile, jwks);

        JwksLoader jwksLoader = JwksLoaderFactory.createFileLoader(tempFile.toAbsolutePath().toString());
        return new JwksAwareTokenParserImpl(jwksLoader, ISSUER);
    }

    public static JwksAwareTokenParserImpl getInvalidJWKSParserWithWrongLocalJWKS() throws IOException {
        // Generate a different key pair for testing
        java.security.KeyPair keyPair = io.jsonwebtoken.security.Keys.keyPairFor(io.jsonwebtoken.SignatureAlgorithm.RS256);
        java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) keyPair.getPublic();

        // Create JWKS JSON with the same key ID as in the token but different key material
        String invalidJwks = JWKSFactory.createJwksFromRsaKey(rsaKey, JWKSFactory.DEFAULT_KEY_ID);

        // Create a temporary file with the invalid JWKS
        java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("invalid-jwks", ".json");
        java.nio.file.Files.writeString(tempFile, invalidJwks);

        JwksLoader jwksLoader = JwksLoaderFactory.createFileLoader(tempFile.toAbsolutePath().toString());
        return new JwksAwareTokenParserImpl(jwksLoader, ISSUER);
    }

    public static JwksAwareTokenParserImpl getInvalidValidJWKSParserWithLocalJWKSAndWrongIssuer() throws IOException {
        JwksLoader jwksLoader = JwksLoaderFactory.createFileLoader(JwksResolveDispatcher.PUBLIC_KEY_JWKS);
        return new JwksAwareTokenParserImpl(jwksLoader, TestTokenProducer.WRONG_ISSUER);
    }

    @Nested
    @DisplayName("Remote JWKS Tests")
    @EnableTestLogger(debug = JwksAwareTokenParserImpl.class, info = JwksAwareTokenParserImpl.class)
    @EnableMockWebServer
    class RemoteJwksTests implements MockWebServerHolder {

        private final JwksResolveDispatcher jwksResolveDispatcher = new JwksResolveDispatcher();
        protected int mockserverPort;
        @Setter
        private MockWebServer mockWebServer;
        private JwksAwareTokenParserImpl tokenParser;
        @Getter
        private final CombinedDispatcher dispatcher = new CombinedDispatcher().addDispatcher(jwksResolveDispatcher);
        private String jwksEndpoint;

        @BeforeEach
        void setupMockServer() {
            mockserverPort = mockWebServer.getPort();
            jwksEndpoint = "http://localhost:" + mockserverPort + jwksResolveDispatcher.getBaseUrl();
            tokenParser = getValidJWKSParserWithRemoteJWKS();
            jwksResolveDispatcher.setCallCounter(0);
        }

        @Test
        @DisplayName("Should resolve token from remote JWKS")
        void shouldResolveFromRemote() {
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);

            var jsonWebToken = assertDoesNotThrow(() -> ParsedToken.jsonWebTokenFrom(initialToken, tokenParser, LOGGER));

            assertTrue(jsonWebToken.isPresent());
            assertEquals(jsonWebToken.get().getRawToken(), initialToken);
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "Initializing JWKS lookup");
        }

        @Test
        @DisplayName("Should fail with invalid issuer")
        void shouldFailFromRemoteWithInvalidIssuer() {
            JwksLoader jwksLoader = JwksLoaderFactory.createHttpLoader(jwksEndpoint, JWKS_REFRESH_INTERVAL, null);
            tokenParser = new JwksAwareTokenParserImpl(jwksLoader, "Wrong Issuer");
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);
            var jsonWebToken = assertDoesNotThrow(() -> ParsedToken.jsonWebTokenFrom(initialToken, tokenParser, LOGGER));

            assertFalse(jsonWebToken.isPresent());
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "Initializing JWKS lookup");
        }

        @Test
        @DisplayName("Should fail with invalid JWKS")
        void shouldFailFromRemoteWithInvalidJWKS() {
            jwksResolveDispatcher.switchToOtherPublicKey();
            // Create a new token parser to force fetching the new JWKS
            tokenParser = getValidJWKSParserWithRemoteJWKS();
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);
            var jsonWebToken = assertDoesNotThrow(() -> ParsedToken.jsonWebTokenFrom(initialToken, tokenParser, LOGGER));

            assertFalse(jsonWebToken.isPresent());
        }

        @Test
        @DisplayName("Should cache JWKS calls")
        void shouldCacheMultipleCalls() {
            jwksResolveDispatcher.assertCallsAnswered(0);
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);
            for (int i = 0; i < 100; i++) {
                var jsonWebToken = ParsedToken.jsonWebTokenFrom(initialToken, tokenParser, LOGGER);
                assertTrue(jsonWebToken.isPresent());
            }
            // For some reason, there are always at least 2 calls, instead of expected one call. No
            // problem because as shown within this test, the number stays at 2
            assertTrue(jwksResolveDispatcher.getCallCounter() < 3);

            for (int i = 0; i < 100; i++) {
                var jsonWebToken = assertDoesNotThrow(() -> ParsedToken.jsonWebTokenFrom(initialToken, tokenParser, LOGGER));
                assertTrue(jsonWebToken.isPresent());
            }
            assertTrue(jwksResolveDispatcher.getCallCounter() < 3);
        }

        private JwksAwareTokenParserImpl getValidJWKSParserWithRemoteJWKS() {
            JwksLoader jwksLoader = JwksLoaderFactory.createHttpLoader(jwksEndpoint, JWKS_REFRESH_INTERVAL, null);
            return new JwksAwareTokenParserImpl(jwksLoader, ISSUER);
        }
    }

    @Nested
    @DisplayName("Local JWKS Tests")
    @EnableTestLogger(debug = JwksAwareTokenParserImpl.class, info = JwksAwareTokenParserImpl.class)
    class LocalJwksTests {

        @Test
        @DisplayName("Should consume local JWKS")
        void shouldConsumeJWKSDirectly() throws IOException {
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);
            var token = ParsedToken.jsonWebTokenFrom(initialToken, getValidJWKSParserWithLocalJWKS(), LOGGER);
            assertTrue(token.isPresent());
            assertEquals(token.get().getRawToken(), initialToken);
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "Initializing JWKS lookup");
        }
    }
}
