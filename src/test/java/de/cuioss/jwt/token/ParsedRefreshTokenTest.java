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

import de.cuioss.jwt.token.adapter.JsonWebToken;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.valueobjects.junit5.contracts.ShouldBeSerializable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.Set;

import static de.cuioss.jwt.token.test.TestTokenProducer.REFRESH_TOKEN;
import static de.cuioss.jwt.token.test.TestTokenProducer.validSignedJWTWithClaims;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@DisplayName("Tests ParsedRefreshToken functionality")
class ParsedRefreshTokenTest implements ShouldBeSerializable<ParsedRefreshToken> {


    @Override
    public ParsedRefreshToken getUnderTest() {
        return new ParsedRefreshToken(validSignedJWTWithClaims(REFRESH_TOKEN));
    }

    @Nested
    @DisplayName("Token Parsing Tests")
    class TokenParsingTests {

        @Test
        @DisplayName("Should handle valid token")
        void shouldHandleValidToken() {
            String initialToken = validSignedJWTWithClaims(REFRESH_TOKEN);
            var parsedRefreshToken = new ParsedRefreshToken(initialToken);

            assertEquals(initialToken, parsedRefreshToken.getRawToken(), "Token string should match original");
            assertFalse(parsedRefreshToken.isEmpty(), "Token should be present");
            assertEquals(TokenType.REFRESH_TOKEN, parsedRefreshToken.getType(), "Token type should be REFRESH_TOKEN");
            assertFalse(parsedRefreshToken.isJwtFormat(), "Should not be recognized as JWT without JsonWebToken");
            assertTrue(parsedRefreshToken.getJsonWebToken().isEmpty(), "JsonWebToken should be empty");
        }

        @Test
        @DisplayName("Should handle invalid token")
        void shouldHandleInvalidToken() {
            var parsedRefreshToken = new ParsedRefreshToken("invalid-token");
            assertFalse(parsedRefreshToken.isEmpty(), "Invalid token should still be wrapped");
            assertEquals("invalid-token", parsedRefreshToken.getRawToken(), "Token string should match original");
            assertFalse(parsedRefreshToken.isJwtFormat(), "Should not be recognized as JWT");
            assertTrue(parsedRefreshToken.getJsonWebToken().isEmpty(), "JsonWebToken should be empty");
        }
        
        @Test
        @DisplayName("Should handle JWT format refresh token")
        void shouldHandleJwtFormatRefreshToken() {
            // Create a mock JSON Web Token
            JsonWebToken jwt = new JsonWebToken() {
                @Override
                public Optional<String> getName() {
                    return Optional.empty();
                }

                @Override
                public Set<String> getClaimNames() {
                    return Set.of("sub", "iss", "typ");
                }

                @Override
                public <T> T getClaim(String claimName) {
                    if ("sub".equals(claimName)) return (T) "testUser";
                    if ("iss".equals(claimName)) return (T) "https://test-issuer.com";
                    if ("typ".equals(claimName)) return (T) "Refresh";
                    return null;
                }

                @Override
                public String getRawToken() {
                    return "jwtRawToken";
                }

                @Override
                public String getIssuer() {
                    return "https://test-issuer.com";
                }

                @Override
                public String getSubject() {
                    return "testUser";
                }

                @Override
                public Optional<Set<String>> getAudience() {
                    return Optional.empty();
                }

                @Override
                public OffsetDateTime getExpirationTime() {
                    return OffsetDateTime.now().plusHours(1);
                }

                @Override
                public OffsetDateTime getIssuedAtTime() {
                    return OffsetDateTime.now().minusMinutes(5);
                }

                @Override
                public Optional<OffsetDateTime> getNotBeforeTime() {
                    return Optional.empty();
                }

                @Override
                public Optional<String> getTokenID() {
                    return Optional.empty();
                }
            };
            
            // Create a refresh token with JWT
            var token = new ParsedRefreshToken("jwtRawToken", jwt);
            
            // Verify
            assertFalse(token.isEmpty(), "Token should not be empty");
            assertEquals("jwtRawToken", token.getRawToken(), "Token string should match original");
            assertEquals(TokenType.REFRESH_TOKEN, token.getType(), "Token type should be REFRESH_TOKEN");
            assertTrue(token.isJwtFormat(), "Should be recognized as JWT format");
            assertTrue(token.getJsonWebToken().isPresent(), "JsonWebToken should be present");
            assertEquals("testUser", token.getJsonWebToken().get().getSubject(), "Subject should match");
            assertEquals("https://test-issuer.com", token.getJsonWebToken().get().getIssuer(), "Issuer should match");
        }
    }
}
