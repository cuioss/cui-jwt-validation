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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.token.IdTokenContent;
import de.cuioss.jwt.validation.flow.IssuerConfig;
import de.cuioss.jwt.validation.security.AlgorithmPreferences;
import de.cuioss.jwt.validation.test.JWKSFactory;
import de.cuioss.jwt.validation.test.KeyMaterialHandler;
import de.cuioss.jwt.validation.test.TestTokenProducer;
import de.cuioss.jwt.validation.test.generator.IDTokenGenerator;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests compliance with the OpenID Connect Core 1.0 specification.
 * 
 * This test class verifies that the library correctly implements the requirements
 * specified in OpenID Connect Core 1.0 for ID tokens.
 * 
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
@DisplayName("OpenID Connect Compliance Tests")
class OpenIDConnectComplianceTest {

    private static final String ISSUER = TestTokenProducer.ISSUER;
    private static final String AUDIENCE = IDTokenGenerator.DEFAULT_CLIENT_ID;
    private static final String CLIENT_ID = IDTokenGenerator.DEFAULT_CLIENT_ID;

    private TokenValidator tokenValidator;
    private IDTokenGenerator idTokenGenerator;

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
                .algorithmPreferences(new AlgorithmPreferences())
                .build();

        // Create validation factory
        TokenValidatorConfig config = TokenValidatorConfig.builder().build();
        tokenValidator = new TokenValidator(config, issuerConfig);

        // Create ID validation generator
        idTokenGenerator = new IDTokenGenerator(false);
    }

    @Nested
    @DisplayName("Section 2: ID Token")
    class IdTokenTests {

        @Test
        @DisplayName("2.2: Required Claims - 'iss' (Issuer) Claim")
        void shouldHandleIssuerClaim() {
            // Given
            String token = idTokenGenerator.next();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertEquals(ISSUER, result.get().getIssuer(),
                    "Issuer claim should match the expected value");
        }

        @Test
        @DisplayName("2.2: Required Claims - 'sub' (Subject) Claim")
        void shouldHandleSubjectClaim() {
            // Given
            String subject = "test-subject";
            String token = Jwts.builder()
                    .issuer(ISSUER)
                    .subject(subject)
                    .issuedAt(Date.from(Instant.now()))
                    .expiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .claim("azp", CLIENT_ID)
                    .claim("aud", CLIENT_ID)
                    .claim("typ", "ID")
                    .header().add("kid", "default-key-id").and()
                    .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                    .compact();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertEquals(subject, result.get().getSubject(),
                    "Subject claim should match the expected value");
        }

        @Test
        @DisplayName("2.2: Required Claims - 'aud' (Audience) Claim")
        void shouldHandleAudienceClaim() {
            // Given
            String token = idTokenGenerator.next();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertEquals(List.of(CLIENT_ID), result.get().getAudience(),
                    "Audience claim should match the expected value");
        }

        @Test
        @DisplayName("2.2: Required Claims - 'exp' (Expiration Time) Claim")
        void shouldHandleExpirationTimeClaim() {
            // Given
            String token = idTokenGenerator.next();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertNotNull(result.get().getExpirationTime(),
                    "Expiration time claim should be present");
            assertFalse(result.get().isExpired(),
                    "Token should not be expired");
        }

        @Test
        @DisplayName("2.2: Required Claims - 'iat' (Issued At) Claim")
        void shouldHandleIssuedAtClaim() {
            // Given
            String token = idTokenGenerator.next();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertNotNull(result.get().getIssuedAtTime(),
                    "Issued At claim should be present");
        }

        @Test
        @DisplayName("2.2: Optional Claims - 'auth_time' (Authentication Time) Claim")
        void shouldHandleAuthTimeClaim() {
            // Given
            Instant authTime = Instant.now().minus(5, ChronoUnit.MINUTES);
            String token = Jwts.builder()
                    .issuer(ISSUER)
                    .subject("test-subject")
                    .issuedAt(Date.from(Instant.now()))
                    .expiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .claim("auth_time", authTime.getEpochSecond())
                    .claim("azp", CLIENT_ID)
                    .claim("aud", CLIENT_ID)
                    .claim("typ", "ID")
                    .header().add("kid", "default-key-id").and()
                    .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                    .compact();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertTrue(result.get().getClaims().containsKey("auth_time"),
                    "Authentication Time claim should be present");
        }

        @Test
        @DisplayName("2.2: Optional Claims - 'nonce' Claim")
        void shouldHandleNonceClaim() {
            // Given
            String nonce = "test-nonce";
            String token = Jwts.builder()
                    .issuer(ISSUER)
                    .subject("test-subject")
                    .issuedAt(Date.from(Instant.now()))
                    .expiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .claim("nonce", nonce)
                    .claim("azp", CLIENT_ID)
                    .claim("aud", CLIENT_ID)
                    .claim("typ", "ID")
                    .header().add("kid", "default-key-id").and()
                    .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                    .compact();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertTrue(result.get().getClaims().containsKey("nonce"),
                    "Nonce claim should be present");
            assertEquals(nonce, result.get().getClaims().get("nonce").getOriginalString(),
                    "Nonce claim should match the expected value");
        }

        @Test
        @DisplayName("2.2: Optional Claims - 'azp' (Authorized Party) Claim")
        void shouldHandleAuthorizedPartyClaim() {
            // Given
            String token = idTokenGenerator.next();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertTrue(result.get().getClaimOption(ClaimName.AUTHORIZED_PARTY).isPresent(),
                    "Authorized Party claim should be present");
            assertEquals(CLIENT_ID, result.get().getClaimOption(ClaimName.AUTHORIZED_PARTY).get().getOriginalString(),
                    "Authorized Party claim should match the expected value");
        }
    }

    @Nested
    @DisplayName("Section 5: Standard Claims")
    class StandardClaimsTests {

        @Test
        @DisplayName("5.1: Standard Claims - 'name' Claim")
        void shouldHandleNameClaim() {
            // Given
            String name = "Test User";
            String token = Jwts.builder()
                    .issuer(ISSUER)
                    .subject("test-subject")
                    .issuedAt(Date.from(Instant.now()))
                    .expiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .claim("name", name)
                    .claim("azp", CLIENT_ID)
                    .claim("aud", CLIENT_ID)
                    .claim("typ", "ID")
                    .header().add("kid", "default-key-id").and()
                    .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                    .compact();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertEquals(name, result.get().getName().orElse(null),
                    "Name claim should match the expected value");
        }

        @Test
        @DisplayName("5.1: Standard Claims - 'email' Claim")
        void shouldHandleEmailClaim() {
            // Given
            String email = "test@example.com";
            String token = Jwts.builder()
                    .issuer(ISSUER)
                    .subject("test-subject")
                    .issuedAt(Date.from(Instant.now()))
                    .expiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .claim("email", email)
                    .claim("azp", CLIENT_ID)
                    .claim("aud", CLIENT_ID)
                    .claim("typ", "ID")
                    .header().add("kid", "default-key-id").and()
                    .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                    .compact();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertEquals(email, result.get().getEmail().orElse(null),
                    "Email claim should match the expected value");
        }

        @Test
        @DisplayName("5.1: Standard Claims - 'preferred_username' Claim")
        void shouldHandlePreferredUsernameClaim() {
            // Given
            String preferredUsername = "testuser";
            String token = Jwts.builder()
                    .issuer(ISSUER)
                    .subject("test-subject")
                    .issuedAt(Date.from(Instant.now()))
                    .expiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .claim("preferred_username", preferredUsername)
                    .claim("azp", CLIENT_ID)
                    .claim("aud", CLIENT_ID)
                    .claim("typ", "ID")
                    .header().add("kid", "default-key-id").and()
                    .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                    .compact();

            // When
            Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

            // Then
            assertTrue(result.isPresent(), "Token should be parsed successfully");
            assertTrue(result.get().getClaimOption(ClaimName.PREFERRED_USERNAME).isPresent(),
                    "Preferred Username claim should be present");
            assertEquals(preferredUsername, result.get().getClaimOption(ClaimName.PREFERRED_USERNAME).get().getOriginalString(),
                    "Preferred Username claim should match the expected value");
        }
    }
}
