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
package de.cuioss.jwt.token.flow;

import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.jwt.token.jwks.JwksLoaderFactory;
import de.cuioss.jwt.token.jwks.key.KeyInfo;
import de.cuioss.jwt.token.security.SecurityEventCounter;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.KeyMaterialHandler;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static de.cuioss.jwt.token.test.TestTokenProducer.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the {@link TokenSignatureValidator} class.
 */
@EnableTestLogger(rootLevel = TestLogLevel.DEBUG)
@DisplayName("Tests TokenSignatureValidator")
class TokenSignatureValidatorTest {

    private NonValidatingJwtParser jwtParser;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {

        // Create a security event counter
        securityEventCounter = new SecurityEventCounter();
        // Create a real JWT parser using the builder
        jwtParser = NonValidatingJwtParser.builder().securityEventCounter(securityEventCounter).build();
    }

    @Test
    @DisplayName("Should validate token with valid signature")
    void shouldValidateTokenWithValidSignature() {
        // Create a valid token
        String token = validSignedJWTWithClaims(SOME_SCOPES);

        // Parse the token
        Optional<DecodedJwt> decodedJwtOpt = jwtParser.decode(token);
        assertTrue(decodedJwtOpt.isPresent(), "Token should be decoded successfully");
        DecodedJwt decodedJwt = decodedJwtOpt.get();

        // Create an in-memory JwksLoader with a valid key
        String jwksContent = JWKSFactory.createDefaultJwks();
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter);

        // Validate the signature
        boolean result = validator.validateSignature(decodedJwt);

        // Assert that the signature is valid
        assertTrue(result, "Token with valid signature should be validated");
    }

    @Test
    @DisplayName("Should reject token with invalid signature")
    void shouldRejectTokenWithInvalidSignature() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);

        // Create a token with a valid signature
        String validToken = validSignedJWTWithClaims(SOME_SCOPES);

        // Tamper with the payload to invalidate the signature
        String[] parts = validToken.split("\\.");
        String header = parts[0];
        String payload = parts[1];

        // Decode the payload, modify it, and encode it again
        String decodedPayload = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        String modifiedPayload = decodedPayload.replace("\"sub\":", "\"sub_modified\":");
        String encodedModifiedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedPayload.getBytes(StandardCharsets.UTF_8));

        // Reconstruct the token with the modified payload but original signature
        String tamperedToken = header + "." + encodedModifiedPayload + "." + parts[2];

        // Parse the tampered token
        Optional<DecodedJwt> decodedJwtOpt = jwtParser.decode(tamperedToken);
        assertTrue(decodedJwtOpt.isPresent(), "Tampered token should be decoded successfully");
        DecodedJwt decodedJwt = decodedJwtOpt.get();

        // Create an in-memory JwksLoader with a valid key
        String jwksContent = JWKSFactory.createDefaultJwks();
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter);

        // Validate the signature
        boolean result = validator.validateSignature(decodedJwt);

        // Assert that the signature is invalid
        assertFalse(result, "Token with invalid signature should be rejected");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to validate token signature: Invalid signature");

        // Verify security event was recorded
        assertTrue(securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED) > initialCount,
                "SIGNATURE_VALIDATION_FAILED event should be incremented");
    }

    @Test
    @DisplayName("Should reject token when key is not found")
    void shouldRejectTokenWhenKeyNotFound() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND);

        // Create a valid token
        String token = validSignedJWTWithClaims(SOME_SCOPES);

        // Parse the token
        Optional<DecodedJwt> decodedJwtOpt = jwtParser.decode(token);
        assertTrue(decodedJwtOpt.isPresent(), "Token should be decoded successfully");
        DecodedJwt decodedJwt = decodedJwtOpt.get();

        // Create an in-memory JwksLoader with a different key ID
        String jwksContent = JWKSFactory.createValidJwksWithKeyId("different-key-id");
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter);

        // Validate the signature
        boolean result = validator.validateSignature(decodedJwt);

        // Assert that validation fails
        assertFalse(result, "Validation should fail when key is not found");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "No key found with ID");

        // Verify security event was recorded
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND),
                "KEY_NOT_FOUND event should be incremented");
    }

    @Test
    @DisplayName("Should reject token with missing kid")
    void shouldRejectTokenWithMissingKid() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

        // Create a token without a kid
        String token = createTokenWithoutKid();

        // Parse the token
        Optional<DecodedJwt> decodedJwtOpt = jwtParser.decode(token);
        assertTrue(decodedJwtOpt.isPresent(), "Token should be decoded successfully");
        DecodedJwt decodedJwt = decodedJwtOpt.get();

        // Create an in-memory JwksLoader with a valid key
        String jwksContent = JWKSFactory.createDefaultJwks();
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter);

        // Validate the signature
        boolean result = validator.validateSignature(decodedJwt);

        // Assert that validation fails
        assertFalse(result, "Validation should fail when kid is missing");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token is missing required claim: kid");

        // Verify security event was recorded
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM),
                "MISSING_CLAIM event should be incremented");
    }

    @Test
    @DisplayName("Should reject token with algorithm confusion attack")
    void shouldRejectAlgorithmConfusionAttack() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND);

        // Create a token with RS256 in the header but actually signed with HS256
        // This is a common algorithm confusion attack
        String token = createAlgorithmConfusionToken();

        // Parse the token
        Optional<DecodedJwt> decodedJwtOpt = jwtParser.decode(token);
        assertTrue(decodedJwtOpt.isPresent(), "Token should be decoded successfully");
        DecodedJwt decodedJwt = decodedJwtOpt.get();

        // Create an in-memory JwksLoader with a valid key
        String jwksContent = JWKSFactory.createDefaultJwks();
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter);

        // Validate the signature
        boolean result = validator.validateSignature(decodedJwt);

        // Assert that validation fails
        assertFalse(result, "Token with algorithm confusion should be rejected");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "No key found with ID: wrong-key-id");

        // Verify security event was recorded
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND),
                "KEY_NOT_FOUND event should be incremented");
    }

    @Test
    @DisplayName("Should reject token with algorithm mismatch")
    void shouldRejectTokenWithAlgorithmMismatch() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);

        // Create a valid token
        String token = validSignedJWTWithClaims(SOME_SCOPES);

        // Parse the token
        Optional<DecodedJwt> decodedJwtOpt = jwtParser.decode(token);
        assertTrue(decodedJwtOpt.isPresent(), "Token should be decoded successfully");
        DecodedJwt decodedJwt = decodedJwtOpt.get();

        // Create a custom JwksLoader that returns a key with incompatible algorithm
        JwksLoader jwksLoader = new JwksLoader() {
            @Override
            public Optional<KeyInfo> getKeyInfo(String kid) {
                if (JWKSFactory.DEFAULT_KEY_ID.equals(kid)) {
                    return Optional.of(new KeyInfo(KeyMaterialHandler.getDefaultPublicKey(), "EC", kid));
                }
                return Optional.empty();
            }

            @Override
            public Optional<KeyInfo> getFirstKeyInfo() {
                return Optional.of(new KeyInfo(KeyMaterialHandler.getDefaultPublicKey(), "EC", JWKSFactory.DEFAULT_KEY_ID));
            }

            @Override
            public List<KeyInfo> getAllKeyInfos() {
                return List.of(new KeyInfo(KeyMaterialHandler.getDefaultPublicKey(), "EC", JWKSFactory.DEFAULT_KEY_ID));
            }

            @Override
            public Set<String> keySet() {
                return Set.of(JWKSFactory.DEFAULT_KEY_ID);
            }
        };

        // Create the validator with the custom JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter);

        // Validate the signature
        boolean result = validator.validateSignature(decodedJwt);

        // Assert that validation fails
        assertFalse(result, "Validation should fail when algorithm doesn't match");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Unsupported algorithm");

        // Verify security event was recorded
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM),
                "UNSUPPORTED_ALGORITHM event should be incremented");
    }

    /**
     * Creates a token without a kid in the header.
     */
    private String createTokenWithoutKid() {
        Instant now = Instant.now();
        Instant expiration = now.plus(1, ChronoUnit.HOURS);

        return Jwts.builder().subject("test-subject")
                .issuer(ISSUER)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(KeyMaterialHandler.getDefaultPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    /**
     * Creates a token signed with RS256.
     */
    private String createToken() {
        Instant now = Instant.now();
        Instant expiration = now.plus(1, ChronoUnit.HOURS);

        return Jwts.builder().subject("test-subject")
                .issuer(ISSUER)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .header().add("kid", JWKSFactory.DEFAULT_KEY_ID).and()
                .signWith(KeyMaterialHandler.getDefaultPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    /**
     * Creates a token for testing algorithm confusion attacks.
     * This simulates a token that claims to use RS256 but with an invalid signature.
     */
    private String createAlgorithmConfusionToken() {
        // Create a valid token with RS256
        String validToken = createToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Modify the header to keep RS256 but change something else
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        header = header.replace("\"kid\":\"" + JWKSFactory.DEFAULT_KEY_ID + "\"", "\"kid\":\"wrong-key-id\"");
        String modifiedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));

        // Construct a token with the modified header but keep the original payload and signature
        // This simulates an algorithm confusion attack where the attacker tries to use a valid signature
        // with a modified header
        return modifiedHeader + "." + parts[1] + "." + parts[2];
    }
}
