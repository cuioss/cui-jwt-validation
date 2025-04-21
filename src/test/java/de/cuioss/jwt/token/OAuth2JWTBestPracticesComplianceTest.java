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

import de.cuioss.jwt.token.domain.token.AccessTokenContent;
import de.cuioss.jwt.token.flow.IssuerConfig;
import de.cuioss.jwt.token.flow.TokenFactoryConfig;
import de.cuioss.jwt.token.flow.TokenSignatureValidator;
import de.cuioss.jwt.token.security.AlgorithmPreferences;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.JwtTokenTamperingUtil;
import de.cuioss.jwt.token.test.KeyMaterialHandler;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.jwt.token.test.generator.AccessTokenGenerator;
import de.cuioss.jwt.token.test.generator.IDTokenGenerator;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests compliance with the OAuth 2.0 JWT Best Current Practices.
 * <p>
 * This test class verifies that the library correctly implements the requirements
 * specified in OAuth 2.0 JWT Best Current Practices.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-bcp-09">OAuth 2.0 JWT Best Current Practices</a>
 */
@EnableGeneratorController
@DisplayName("OAuth 2.0 JWT Best Practices Compliance Tests")
class OAuth2JWTBestPracticesComplianceTest {

    private static final String ISSUER = TestTokenProducer.ISSUER;
    private static final String AUDIENCE = "test-client";
    private static final String CLIENT_ID = "test-client";

    private TokenFactory tokenFactory;
    private AccessTokenGenerator accessTokenGenerator;

    @BeforeEach
    void setUp() {
        // Get the default JWKS content
        String jwksContent = JWKSFactory.createDefaultJwks();

        // Create issuer config
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .expectedClientId(CLIENT_ID)
                .jwksContent(jwksContent)
                .build();

        // Create token factory
        TokenFactoryConfig config = TokenFactoryConfig.builder().build();
        tokenFactory = new TokenFactory(config, issuerConfig);

        // Create access token generator
        accessTokenGenerator = new AccessTokenGenerator(false);
    }

    @Nested
    @DisplayName("Section 3.1: Validation of Audience")
    class AudienceValidationTests {

        @Test
        @DisplayName("3.1: Validate audience claim")
        void shouldValidateAudienceClaim() {
            // Given
            String token = accessTokenGenerator.next();

            // When
            Optional<AccessTokenContent> result = tokenFactory.createAccessToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertTrue(result.get().getAudience().isPresent(), "Audience claim should be present");
            assertTrue(result.get().getAudience().get().contains(AUDIENCE),
                    "Audience claim should contain the expected value");
        }

        @Test
        @DisplayName("3.1: Reject token with incorrect audience")
        void shouldRejectTokenWithIncorrectAudience() {
            // Given
            String wrongAudience = "wrong-audience";
            String token = Jwts.builder()
                    .issuer(ISSUER)
                    .subject("test-subject")
                    .issuedAt(Date.from(Instant.now()))
                    .expiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .claim("azp", CLIENT_ID)
                    .claim("aud", wrongAudience)
                    .header().add("kid", "default-key-id").and()
                    .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                    .compact();

            // When
            Optional<AccessTokenContent> result = tokenFactory.createAccessToken(token);

            // Then
            assertFalse(result.isPresent(), "Token with incorrect audience should be rejected");
        }
    }

    @Nested
    @DisplayName("Section 3.2: Validation of Issuer")
    class IssuerValidationTests {

        @Test
        @DisplayName("3.2: Validate issuer claim")
        void shouldValidateIssuerClaim() {
            // Given
            String token = accessTokenGenerator.next();

            // When
            Optional<AccessTokenContent> result = tokenFactory.createAccessToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertEquals(ISSUER, result.get().getIssuer(),
                    "Issuer claim should match the expected value");
        }

        @Test
        @DisplayName("3.2: Reject token with incorrect issuer")
        void shouldRejectTokenWithIncorrectIssuer() {
            // Given
            String wrongIssuer = "https://wrong-issuer.com";
            String token = Jwts.builder()
                    .issuer(wrongIssuer)
                    .subject("test-subject")
                    .issuedAt(Date.from(Instant.now()))
                    .expiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .claim("azp", CLIENT_ID)
                    .claim("aud", AUDIENCE)
                    .header().add("kid", "default-key-id").and()
                    .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                    .compact();

            // When
            Optional<AccessTokenContent> result = tokenFactory.createAccessToken(token);

            // Then
            assertFalse(result.isPresent(), "Token with incorrect issuer should be rejected");
        }
    }

    @Nested
    @DisplayName("Section 3.3: Validation of Signature")
    @EnableTestLogger(trace = TokenSignatureValidator.class)
    class SignatureValidationTests {

        @Test
        @DisplayName("3.3: Validate token signature")
        void shouldValidateTokenSignature() {
            // Given
            String token = accessTokenGenerator.next();

            // When
            Optional<AccessTokenContent> result = tokenFactory.createAccessToken(token);

            // Then
            assertTrue(result.isPresent(), "Token with valid signature should be parsed successfully");
        }

        @DisplayName("3.3b: Reject access-token with invalid signature")
        @ParameterizedTest
        @TypeGeneratorSource(value = AccessTokenGenerator.class, count = 50)
        void shouldRejectAccessTokenWithInvalidSignature(String token) {

            // Tamper with the signature by changing the last character
            String tamperedToken = JwtTokenTamperingUtil.tamperWithToken(token);

            assertNotEquals(tamperedToken, token, "Token should be tampered");
            // When
            var result = tokenFactory.createAccessToken(tamperedToken);

            // Then
            assertFalse(result.isPresent(), "Token with invalid signature should be rejected, offending token: " + tamperedToken);
        }

        @DisplayName("3.3b: Reject id-token with invalid signature")
        @ParameterizedTest
        @TypeGeneratorSource(value = IDTokenGenerator.class, count = 50)
        void shouldRejectIDTokenWithInvalidSignature(String token) {

            // Tamper with the signature by changing the last character
            String tamperedToken = JwtTokenTamperingUtil.tamperWithToken(token);

            assertNotEquals(tamperedToken, token, "Token should be tampered");
            // When
            var result = tokenFactory.createIdToken(tamperedToken);

            // Then
            assertFalse(result.isPresent(), "Token with invalid signature should be rejected, offending token: " + tamperedToken);
        }
    }

    @Nested
    @DisplayName("Section 3.8: Token Lifetimes")
    class TokenLifetimeTests {

        @Test
        @DisplayName("3.8: Validate token expiration")
        void shouldValidateTokenExpiration() {
            // Given
            String token = accessTokenGenerator.next();

            // When
            Optional<AccessTokenContent> result = tokenFactory.createAccessToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertNotNull(result.get().getExpirationTime(),
                    "Expiration time claim should be present");
            assertFalse(result.get().isExpired(),
                    "Token should not be expired");
        }

        @Test
        @DisplayName("3.8: Reject expired token")
        void shouldRejectExpiredToken() {
            // Given
            Instant expiredTime = Instant.now().minus(1, ChronoUnit.HOURS);
            String token = TestTokenProducer.validSignedJWTExpireAt(expiredTime);

            // When
            Optional<AccessTokenContent> result = tokenFactory.createAccessToken(token);

            // Then
            assertFalse(result.isPresent(), "Expired token should be rejected");
        }
    }

    @Nested
    @DisplayName("Section 3.11: Maximum Token Size")
    class TokenSizeTests {

        @Test
        @DisplayName("3.11: Validate token size limits")
        void shouldRespectTokenSizeLimits() {
            // Given
            int customMaxSize = 1024;
            String largeToken = "a".repeat(customMaxSize + 1);

            // Create TokenFactory with custom token size limits
            TokenFactoryConfig customConfig = TokenFactoryConfig.builder()
                    .maxTokenSize(customMaxSize)
                    .build();
            var factory = new TokenFactory(customConfig, IssuerConfig.builder()
                    .issuer(ISSUER)
                    .expectedAudience(AUDIENCE)
                    .expectedClientId(CLIENT_ID)
                    .jwksContent(JWKSFactory.createDefaultJwks())
                    .algorithmPreferences(new AlgorithmPreferences())
                    .build());

            // When
            Optional<AccessTokenContent> result = factory.createAccessToken(largeToken);

            // Then
            assertFalse(result.isPresent(), "Token exceeding max size should be rejected");
        }

        @Test
        @DisplayName("3.11: Default token size limit should be 8KB")
        void defaultTokenSizeLimitShouldBe8KB() {
            // Given
            TokenFactoryConfig config = TokenFactoryConfig.builder().build();

            // Then
            assertEquals(8192, config.getMaxTokenSize(),
                    "Default token size limit should be 8KB (8192 bytes)");
        }
    }
}