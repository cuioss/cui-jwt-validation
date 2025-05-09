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
package de.cuioss.jwt.validation.test;

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
    void shouldCreateValidSignedJWTWithClaims() {
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        assertNotNull(token);

        // Parse the validation using JJWT
        Jws<Claims> parsedToken = Jwts.parser()
                .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                .build().parseSignedClaims(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getPayload().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getPayload().getSubject());
        assertTrue(parsedToken.getPayload().containsKey("scope"));
    }

    @Test
    void shouldCreateValidSignedEmptyJWT() {
        String token = TestTokenProducer.validSignedEmptyJWT();
        assertNotNull(token);

        // Parse the validation using JJWT
        Jws<Claims> parsedToken = Jwts.parser()
                .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                .build().parseSignedClaims(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getPayload().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getPayload().getSubject());
    }

    @Test
    void shouldCreateValidSignedJWTWithClaimsAndCustomSubject() {
        String customSubject = "custom-subject";
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES, customSubject);
        assertNotNull(token);

        // Parse the validation using JJWT
        Jws<Claims> parsedToken = Jwts.parser()
                .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                .build().parseSignedClaims(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getPayload().getIssuer());
        assertEquals(customSubject, parsedToken.getPayload().getSubject());
        assertTrue(parsedToken.getPayload().containsKey("scope"));
    }

    @Test
    void shouldCreateValidSignedJWTWithExpiration() {
        Instant expireAt = Instant.now().plus(1, ChronoUnit.HOURS);
        String token = TestTokenProducer.validSignedJWTExpireAt(expireAt);
        assertNotNull(token);

        // Parse the validation using JJWT
        Jws<Claims> parsedToken = Jwts.parser()
                .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                .build().parseSignedClaims(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getPayload().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getPayload().getSubject());

        // Check expiration
        Date expiration = parsedToken.getPayload().getExpiration();
        assertNotNull(expiration);
        assertEquals(expireAt.getEpochSecond(), expiration.toInstant().getEpochSecond());
    }

    @Test
    void shouldCreateValidSignedJWTWithNotBefore() {
        // Set notBefore to 1 minute in the past to avoid PrematureJwtException
        Instant notBefore = Instant.now().minus(1, ChronoUnit.MINUTES);
        String token = TestTokenProducer.validSignedJWTWithNotBefore(notBefore);
        assertNotNull(token);

        // Parse the validation using JJWT
        Jws<Claims> parsedToken = Jwts.parser()
                .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                .build().parseSignedClaims(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getPayload().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getPayload().getSubject());

        // Check nbf claim
        assertTrue(parsedToken.getPayload().containsKey("nbf"));
        assertEquals(notBefore.getEpochSecond(), ((Number) parsedToken.getPayload().get("nbf")).longValue());
    }

    @Test
    void shouldHandleNullClaimsPath() {
        String token = TestTokenProducer.validSignedJWTWithClaims(null);
        assertNotNull(token);

        // Parse the validation using JJWT
        Jws<Claims> parsedToken = Jwts.parser()
                .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                .build().parseSignedClaims(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getPayload().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getPayload().getSubject());
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

        // Parse the validation using JJWT directly
        Jws<Claims> parsedToken = Jwts.parser()
                .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                .build().parseSignedClaims(token);

        assertNotNull(parsedToken);
        assertEquals(TestTokenProducer.ISSUER, parsedToken.getPayload().getIssuer());
        assertEquals(TestTokenProducer.SUBJECT, parsedToken.getPayload().getSubject());
        assertTrue(parsedToken.getPayload().containsKey("scope"));
    }

}
