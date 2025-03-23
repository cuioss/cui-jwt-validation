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

import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.jwt.token.util.DecodedJwt;
import de.cuioss.jwt.token.util.NonValidatingJwtParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Tests TokenFactory functionality")
class TokenFactoryTest {

    private TokenFactory tokenFactory;

    @BeforeEach
    void setUp() throws IOException {
        tokenFactory = TokenFactory.builder()
                .addParser(JwksAwareTokenParserImplTest.getValidJWKSParserWithLocalJWKS())
                .build();
    }

    @Nested
    @DisplayName("Token Size Validation Tests")
    class TokenSizeValidationTests {

        @Test
        @DisplayName("Should create TokenFactory with builder and default token size limits")
        void shouldCreateTokenFactoryWithBuilder() throws IOException {
            // Create TokenFactory using builder
            TokenFactory factory = TokenFactory.builder()
                    .addParser(JwksAwareTokenParserImplTest.getValidJWKSParserWithLocalJWKS())
                    .build();

            // Verify it works with a valid token
            var token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
            var parsedToken = factory.createAccessToken(token);

            assertTrue(parsedToken.isPresent(), "Token should be parsed successfully");
        }

        @Test
        @DisplayName("Should respect custom token size limits")
        void shouldRespectCustomTokenSizeLimits() throws IOException {
            // Create a token that exceeds the custom max size but is smaller than the default
            int customMaxSize = 1024;
            StringBuilder largeToken = new StringBuilder();
            largeToken.append("a".repeat(customMaxSize + 1));

            // Create TokenFactory with custom token size limits
            TokenFactory factory = TokenFactory.builder()
                    .addParser(JwksAwareTokenParserImplTest.getValidJWKSParserWithLocalJWKS())
                    .maxTokenSize(customMaxSize)
                    .build();

            // Verify it rejects a token that exceeds the custom max size
            var parsedToken = factory.createAccessToken(largeToken.toString());

            assertFalse(parsedToken.isPresent(), "Token exceeding custom max size should be rejected");
        }

        @Test
        @DisplayName("Should respect custom payload size limits")
        void shouldRespectCustomPayloadSizeLimits() throws IOException {
            // Create TokenFactory with custom payload size limits
            TokenFactory factory = TokenFactory.builder()
                    .addParser(JwksAwareTokenParserImplTest.getValidJWKSParserWithLocalJWKS())
                    .maxPayloadSize(100)
                    .build();

            // Create a token with a large payload by creating a large string claim
            StringBuilder largePayload = new StringBuilder();
            largePayload.append("a".repeat(200));

            // Create a JWT with the large payload using io.jsonwebtoken
            String token = io.jsonwebtoken.Jwts.builder()
                    .setIssuer(TestTokenProducer.ISSUER)
                    .setSubject("test-subject")
                    .claim("large-claim", largePayload.toString())
                    .signWith(de.cuioss.jwt.token.test.KeyMaterialHandler.getDefaultPrivateKey(),
                            io.jsonwebtoken.SignatureAlgorithm.RS256)
                    .compact();

            // Verify it rejects a token with a payload that exceeds the custom max size
            var parsedToken = factory.createAccessToken(token);

            assertFalse(parsedToken.isPresent(), "Token with payload exceeding custom max size should be rejected");
        }
    }

    @Nested
    @DisplayName("Token Creation Tests")
    class TokenCreationTests {

        @Test
        @DisplayName("Should create access token")
        void shouldCreateAccessToken() {
            var token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);

            // Use NonValidatingJwtParser to validate the token
            var tokenParser = NonValidatingJwtParser.builder().build();
            var issuer = tokenParser.decode(token).flatMap(DecodedJwt::getIssuer);

            assertTrue(issuer.isPresent(), "Issuer should be present");
            assertEquals(TestTokenProducer.ISSUER, issuer.get(), "Issuer should match expected value");
        }

        @Test
        @DisplayName("Should create ID token")
        void shouldCreateIdToken() {
            var token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_ID_TOKEN);

            // Use NonValidatingJwtParser to validate the token
            var tokenParser = NonValidatingJwtParser.builder().build();
            var issuer = tokenParser.decode(token).flatMap(DecodedJwt::getIssuer);

            assertTrue(issuer.isPresent(), "Issuer should be present");
            assertEquals(TestTokenProducer.ISSUER, issuer.get(), "Issuer should match expected value");
        }

        @Test
        @DisplayName("Should create refresh token")
        void shouldCreateRefreshToken() {
            var token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.REFRESH_TOKEN);
            var parsedToken = tokenFactory.createRefreshToken(token);

            assertTrue(parsedToken.isPresent(), "Token should be present");
            assertNotNull(parsedToken.get().getTokenString(), "Token string should not be null");
        }
    }

    @Nested
    @DisplayName("Token Validation Error Tests")
    class TokenValidationErrorTests {

        @Test
        @DisplayName("Should handle expired token")
        void shouldHandleExpiredToken() {
            var expiredToken = TestTokenProducer.validSignedJWTExpireAt(
                    Instant.now().minus(1, ChronoUnit.HOURS));

            var token = tokenFactory.createAccessToken(expiredToken);

            assertFalse(token.isPresent(), "Expired token should not be valid");
        }

        @Test
        @DisplayName("Should handle invalid issuer")
        void shouldHandleInvalidIssuer() throws IOException {
            var wrongIssuerTokenFactory = TokenFactory.builder()
                    .addParser(JwksAwareTokenParserImplTest.getInvalidValidJWKSParserWithLocalJWKSAndWrongIssuer())
                    .build();
            var token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
            var parsedToken = wrongIssuerTokenFactory.createAccessToken(token);

            assertFalse(parsedToken.isPresent(), "Token with invalid issuer should not be valid");
        }

        @Test
        @DisplayName("Should handle invalid signature")
        void shouldHandleInvalidSignature() throws IOException {
            var wrongSignatureTokenFactory = TokenFactory.builder()
                    .addParser(JwksAwareTokenParserImplTest.getInvalidJWKSParserWithWrongLocalJWKS())
                    .build();
            var token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
            var parsedToken = wrongSignatureTokenFactory.createAccessToken(token);

            assertFalse(parsedToken.isPresent(), "Token with invalid signature should not be valid");
        }
    }
}
