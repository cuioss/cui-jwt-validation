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
package de.cuioss.jwt.token.adapter;

import de.cuioss.jwt.token.JwksAwareTokenParserImplTest;
import de.cuioss.jwt.token.TokenFactory;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;

import static de.cuioss.jwt.token.test.TestTokenProducer.validSignedJWTWithNotBefore;
import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests JwtAdapter functionality")
class JwtAdapterTest {

    private TokenFactory tokenFactory;

    @BeforeEach
    void setUp() {
        tokenFactory = TokenFactory.builder()
                .addParser(JwksAwareTokenParserImplTest.getValidJWKSParserWithLocalJWKS())
                .build();
    }

    @Nested
    @DisplayName("Not Before Time Tests")
    class NotBeforeTimeTests {

        @Test
        @DisplayName("Should handle token without explicit nbf claim")
        void shouldHandleTokenWithoutNotBeforeClaim() {
            // Currently smallrye add nbf claim automatically
            String initialToken = validSignedJWTWithNotBefore(OffsetDateTime.now().toInstant());

            var token = tokenFactory.createAccessToken(initialToken);
            assertTrue(token.isPresent(), "Token should be present for valid input");

            // Get the underlying JsonWebToken from the ParsedToken
            JsonWebToken jsonWebToken = token.get().getJsonWebToken();
            assertInstanceOf(JwtAdapter.class, jsonWebToken, "JsonWebToken should be a JwtAdapter");

            // Just verify that the method doesn't throw an exception
            // and returns something (either empty or a value)
            assertDoesNotThrow(jsonWebToken::getNotBeforeTime);
        }

        @Test
        @DisplayName("Should handle token with nbf claim")
        void shouldHandleTokenWithNotBeforeClaim() {
            // Create a token with nbf set to 5 minutes ago
            java.time.Instant notBeforeTime = java.time.Instant.now().minusSeconds(300);
            String initialToken = validSignedJWTWithNotBefore(notBeforeTime);

            var token = tokenFactory.createAccessToken(initialToken);
            assertTrue(token.isPresent(), "Token should be present for nbf in the past");

            // Get the underlying JsonWebToken from the ParsedToken
            JsonWebToken jsonWebToken = token.get().getJsonWebToken();
            assertInstanceOf(JwtAdapter.class, jsonWebToken, "JsonWebToken should be a JwtAdapter");

            var parsedNotBeforeTime = jsonWebToken.getNotBeforeTime();
            assertTrue(parsedNotBeforeTime.isPresent(), "Not Before Time should be present");
            assertTrue(parsedNotBeforeTime.get().isBefore(OffsetDateTime.now()), "Not Before Time should be in the past");
        }
    }

    @Nested
    @DisplayName("Optional Field Tests")
    class OptionalFieldTests {

        @Test
        @DisplayName("Should handle optional fields correctly")
        void shouldHandleOptionalFields() {
            // Create a token with some optional fields
            String initialToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);

            var token = tokenFactory.createAccessToken(initialToken);
            assertTrue(token.isPresent(), "Token should be present for valid input");

            // Get the underlying JsonWebToken from the ParsedToken
            JsonWebToken jsonWebToken = token.get().getJsonWebToken();
            assertInstanceOf(JwtAdapter.class, jsonWebToken, "JsonWebToken should be a JwtAdapter");

            // Test getName() returns Optional
            assertNotNull(jsonWebToken.getName(), "getName() should not return null");

            // Test getTokenID() returns Optional
            assertNotNull(jsonWebToken.getTokenID(), "getTokenID() should not return null");

            // Test getAudience() returns Optional
            assertNotNull(jsonWebToken.getAudience(), "getAudience() should not return null");

        }
    }

    @Nested
    @DisplayName("Time Field Tests")
    class TimeFieldTests {

        @Test
        @DisplayName("Should handle time fields correctly")
        void shouldHandleTimeFields() {
            // Create a token with specific expiration time
            Instant expiresAt = Instant.now().plusSeconds(300);
            String initialToken = TestTokenProducer.validSignedJWTExpireAt(expiresAt);

            var token = tokenFactory.createAccessToken(initialToken);
            assertTrue(token.isPresent(), "Token should be present for valid input");

            // Get the underlying JsonWebToken from the ParsedToken
            JsonWebToken jsonWebToken = token.get().getJsonWebToken();
            assertInstanceOf(JwtAdapter.class, jsonWebToken, "JsonWebToken should be a JwtAdapter");

            // Test getExpirationTime() returns OffsetDateTime
            OffsetDateTime expTime = jsonWebToken.getExpirationTime();
            assertNotNull(expTime, "getExpirationTime() should not return null");
            assertTrue(expTime.isAfter(OffsetDateTime.now()), "Expiration time should be in the future");

            // Test getIssuedAtTime() returns OffsetDateTime
            OffsetDateTime iatTime = jsonWebToken.getIssuedAtTime();
            assertNotNull(iatTime, "getIssuedAtTime() should not return null");
            assertTrue(iatTime.isBefore(OffsetDateTime.now()), "Issued at time should be in the past");

            // Verify the times are close to what we set
            // In TestTokenProducer.validSignedJWTExpireAt, issuedAt is set to 5 minutes before expireAt
            OffsetDateTime expectedIssuedAt = OffsetDateTime.ofInstant(expiresAt, ZoneId.systemDefault()).minusMinutes(5);
            OffsetDateTime expectedExpiresAt = OffsetDateTime.ofInstant(expiresAt, ZoneId.systemDefault());

            long issuedAtDiff = Math.abs(expectedIssuedAt.toEpochSecond() - iatTime.toEpochSecond());
            long expiresAtDiff = Math.abs(expectedExpiresAt.toEpochSecond() - expTime.toEpochSecond());

            assertTrue(issuedAtDiff <= 1, "Issued at time should be within 1 second of expected time");
            assertTrue(expiresAtDiff <= 1, "Expiration time should be within 1 second of expected time");
        }
    }
}
