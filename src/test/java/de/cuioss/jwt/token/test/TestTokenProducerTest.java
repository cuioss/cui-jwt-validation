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
package de.cuioss.jwt.token.test;

import de.cuioss.jwt.token.JwtParser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TestTokenProducer}.
 */
class TestTokenProducerTest {

    @Test
    void shouldGetDefaultTokenParser() {
        JwtParser parser = TestTokenProducer.getDefaultTokenParser();
        assertNotNull(parser);
    }

    @Test
    void shouldGetWrongIssuerTokenParser() {
        JwtParser parser = TestTokenProducer.getWrongIssuerTokenParser();
        assertNotNull(parser);
    }

    @Test
    void shouldGetWrongSignatureTokenParser() {
        JwtParser parser = TestTokenProducer.getWrongSignatureTokenParser();
        assertNotNull(parser);
    }

    @Test
    void shouldCreateValidSignedJWTWithClaims() {
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        assertNotNull(token);

        // Parse the token using JJWT
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(KeyMaterialHandler.getDefaultPrivateKey())
                .build()
                .parseClaimsJws(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getBody().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getBody().getSubject());
        assertTrue(parsedToken.getBody().containsKey("scope"));
    }

    @Test
    void shouldCreateValidSignedEmptyJWT() {
        String token = TestTokenProducer.validSignedEmptyJWT();
        assertNotNull(token);

        // Parse the token using JJWT
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(KeyMaterialHandler.getDefaultPrivateKey())
                .build()
                .parseClaimsJws(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getBody().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getBody().getSubject());
    }

    @Test
    void shouldCreateValidSignedJWTWithClaimsAndCustomSubject() {
        String customSubject = "custom-subject";
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES, customSubject);
        assertNotNull(token);

        // Parse the token using JJWT
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(KeyMaterialHandler.getDefaultPrivateKey())
                .build()
                .parseClaimsJws(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getBody().getIssuer());
        assertEquals(customSubject, parsedToken.getBody().getSubject());
        assertTrue(parsedToken.getBody().containsKey("scope"));
    }

    @Test
    void shouldCreateValidSignedJWTWithExpiration() {
        Instant expireAt = Instant.now().plus(1, ChronoUnit.HOURS);
        String token = TestTokenProducer.validSignedJWTExpireAt(expireAt);
        assertNotNull(token);

        // Parse the token using JJWT
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(KeyMaterialHandler.getDefaultPrivateKey())
                .build()
                .parseClaimsJws(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getBody().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getBody().getSubject());

        // Check expiration
        Date expiration = parsedToken.getBody().getExpiration();
        assertNotNull(expiration);
        assertEquals(expireAt.getEpochSecond(), expiration.toInstant().getEpochSecond());
    }

    @Test
    void shouldCreateValidSignedJWTWithNotBefore() {
        // Set notBefore to 1 minute in the past to avoid PrematureJwtException
        Instant notBefore = Instant.now().minus(1, ChronoUnit.MINUTES);
        String token = TestTokenProducer.validSignedJWTWithNotBefore(notBefore);
        assertNotNull(token);

        // Parse the token using JJWT
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(KeyMaterialHandler.getDefaultPrivateKey())
                .build()
                .parseClaimsJws(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getBody().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getBody().getSubject());

        // Check nbf claim
        assertTrue(parsedToken.getBody().containsKey("nbf"));
        assertEquals(notBefore.getEpochSecond(), ((Number) parsedToken.getBody().get("nbf")).longValue());
    }

    @Test
    void shouldHandleNullClaimsPath() {
        String token = TestTokenProducer.validSignedJWTWithClaims(null);
        assertNotNull(token);

        // Parse the token using JJWT
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(KeyMaterialHandler.getDefaultPrivateKey())
                .build()
                .parseClaimsJws(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getBody().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getBody().getSubject());
    }

    @Test
    void shouldHandleInvalidClaimsPath() {
        // This should not throw an exception but handle the error gracefully
        assertThrows(RuntimeException.class, () ->
                TestTokenProducer.validSignedJWTWithClaims("non-existent-file.json"));
    }

    @Test
    void shouldVerifyTokenWithJwt() {
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);

        // Parse the token using JJWT directly
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(KeyMaterialHandler.getDefaultPrivateKey())
                .build()
                .parseClaimsJws(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getBody().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getBody().getSubject());
        assertTrue(parsedToken.getBody().containsKey("scope"));
    }

    @Test
    void shouldRejectTokenWithWrongIssuerParser() {
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        JwtParser parser = TestTokenProducer.getWrongIssuerTokenParser();

        // The wrong issuer parser should reject the token
        var parsedToken = parser.parse(token);
        assertFalse(parsedToken.isPresent(), "Token should be rejected with wrong issuer parser");
    }

    @Test
    void shouldRejectTokenWithWrongSignatureParser() {
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        JwtParser parser = TestTokenProducer.getWrongSignatureTokenParser();

        // The wrong signature parser should reject the token
        var parsedToken = parser.parse(token);
        assertFalse(parsedToken.isPresent(), "Token should be rejected with wrong signature parser");
    }
}
