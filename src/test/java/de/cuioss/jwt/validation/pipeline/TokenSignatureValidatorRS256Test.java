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
package de.cuioss.jwt.validation.pipeline;

import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksLoaderFactory;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.jwt.validation.test.JwtTokenTamperingUtil;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

import static de.cuioss.jwt.validation.test.TestTokenProducer.ISSUER;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the {@link TokenSignatureValidator} class focusing on RS256 algorithm.
 */
@EnableTestLogger(rootLevel = TestLogLevel.DEBUG)
@DisplayName("Tests TokenSignatureValidator with RS256 algorithm")
class TokenSignatureValidatorRS256Test {

    private NonValidatingJwtParser jwtParser;
    private SecurityEventCounter securityEventCounter;
    private JwksLoader jwksLoader;
    private TokenSignatureValidator validator;

    @BeforeEach
    void setUp() {
        // Create a security event counter
        securityEventCounter = new SecurityEventCounter();

        // Create a real JWT parser using the builder
        jwtParser = NonValidatingJwtParser.builder().securityEventCounter(securityEventCounter).build();

        // Create an in-memory JwksLoader with a valid key
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        validator = new TokenSignatureValidator(jwksLoader, securityEventCounter);
    }

    @Test
    @DisplayName("Should validate token with valid RS256 signature")
    void shouldValidateTokenWithValidRS256Signature() {
        // Create a valid token with RS256
        String token = createTokenRS256();

        // Parse the token
        Optional<DecodedJwt> decodedJwtOpt = jwtParser.decode(token);
        assertTrue(decodedJwtOpt.isPresent(), "Token should be decoded successfully");
        DecodedJwt decodedJwt = decodedJwtOpt.get();

        // Validate the signature
        boolean result = validator.validateSignature(decodedJwt);

        // Assert that the signature is valid
        assertTrue(result, "Token with valid RS256 signature should be validated");
    }

    @Test
    @DisplayName("Should reject token with tampered RS256 signature")
    void shouldRejectTokenWithTamperedRS256Signature() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);

        // Create a valid token with RS256
        String validToken = createTokenRS256();

        // Tamper with the signature
        String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(
                validToken, JwtTokenTamperingUtil.TamperingStrategy.MODIFY_SIGNATURE_LAST_CHAR);

        // Parse the tampered token
        Optional<DecodedJwt> decodedJwtOpt = jwtParser.decode(tamperedToken);
        assertTrue(decodedJwtOpt.isPresent(), "Tampered token should be decoded successfully");
        DecodedJwt decodedJwt = decodedJwtOpt.get();

        // Validate the signature
        boolean result = validator.validateSignature(decodedJwt);

        // Assert that the signature is invalid
        assertFalse(result, "Token with tampered RS256 signature should be rejected");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to validate validation signature");

        // Verify security event was recorded
        assertTrue(securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED) > initialCount,
                "SIGNATURE_VALIDATION_FAILED event should be incremented");
    }

    /**
     * Creates a token signed with RS256.
     *
     * @return a signed JWT token
     */
    private String createTokenRS256() {
        Instant now = Instant.now();
        Instant expiration = now.plus(1, ChronoUnit.HOURS);

        return Jwts.builder().subject("test-subject")
                .issuer(ISSUER)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .header().add("kid", InMemoryJWKSFactory.DEFAULT_KEY_ID).and()
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }
}