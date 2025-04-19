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

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.claim.ClaimName;
import de.cuioss.jwt.token.domain.token.AccessTokenContent;
import de.cuioss.jwt.token.domain.token.IdTokenContent;
import de.cuioss.jwt.token.domain.token.RefreshTokenContent;
import de.cuioss.jwt.token.test.generator.DecodedJwtGenerator;
import de.cuioss.jwt.token.test.generator.RefreshTokenGenerator;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link TokenBuilder}.
 */
@EnableGeneratorController
@DisplayName("Tests TokenBuilder functionality")
class TokenBuilderTest {

    private TokenBuilder tokenBuilder;
    private final RefreshTokenGenerator refreshTokenGenerator = new RefreshTokenGenerator(false);

    @BeforeEach
    void setUp() {
        // Create a simple IssuerConfig for testing
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer("https://test-issuer.com")
                .build();

        tokenBuilder = new TokenBuilder(issuerConfig);
    }

    @Test
    @DisplayName("createRefreshToken should create RefreshTokenContent")
    void createRefreshTokenShouldCreateRefreshTokenContent() {
        // Given
        String token = refreshTokenGenerator.next();

        // When
        Optional<RefreshTokenContent> result = tokenBuilder.createRefreshToken(token);

        // Then
        assertTrue(result.isPresent(), "Should return RefreshTokenContent");
        RefreshTokenContent refreshTokenContent = result.get();

        // Verify token type
        assertEquals(TokenType.REFRESH_TOKEN, refreshTokenContent.getTokenType(), "Token type should be REFRESH_TOKEN");

        // Verify raw token
        assertEquals(token, refreshTokenContent.getRawToken(), "Raw token should match");
    }


    @Nested
    @DisplayName("AccessToken Tests")
    class AccessTokenTests {

        @Test
        @DisplayName("createAccessToken should create AccessTokenContent from DecodedJwt")
        void createAccessTokenShouldCreateAccessTokenContent() {
            // Given a DecodedJwt with ACCESS_TOKEN type
            DecodedJwt decodedJwt = new DecodedJwtGenerator(TokenType.ACCESS_TOKEN).next();

            // When creating an AccessTokenContent
            Optional<AccessTokenContent> result = tokenBuilder.createAccessToken(decodedJwt);

            // Then
            assertTrue(result.isPresent(), "Should return AccessTokenContent");
            AccessTokenContent accessTokenContent = result.get();

            // Verify token type
            assertEquals(TokenType.ACCESS_TOKEN, accessTokenContent.getTokenType(), "Token type should be ACCESS_TOKEN");

            // Verify raw token
            assertEquals(decodedJwt.getRawToken(), accessTokenContent.getRawToken(), "Raw token should match");

            // Verify claims are extracted
            assertFalse(accessTokenContent.getClaims().isEmpty(), "Claims should not be empty");
            assertTrue(accessTokenContent.getClaims().containsKey(ClaimName.SUBJECT.getName()),
                    "Claims should contain subject");
            assertTrue(accessTokenContent.getClaims().containsKey(ClaimName.ISSUER.getName()),
                    "Claims should contain issuer");
        }

        @Test
        @DisplayName("createAccessToken should handle DecodedJwt with missing body")
        void createAccessTokenShouldHandleDecodedJwtWithMissingBody() {
            // Given a DecodedJwt with null body
            DecodedJwt decodedJwt = new DecodedJwt(null, null, null, new String[]{"", "", ""}, "test-token");

            // When creating an AccessTokenContent
            Optional<AccessTokenContent> result = tokenBuilder.createAccessToken(decodedJwt);

            // Then
            assertTrue(result.isEmpty(), "Should return empty Optional when body is missing");
        }
    }

    @Nested
    @DisplayName("IdToken Tests")
    class IdTokenTests {

        @Test
        @DisplayName("createIdToken should create IdTokenContent from DecodedJwt")
        void createIdTokenShouldCreateIdTokenContent() {
            // Given a DecodedJwt with ID_TOKEN type
            DecodedJwt decodedJwt = new DecodedJwtGenerator(TokenType.ID_TOKEN).next();

            // When creating an IdTokenContent
            Optional<IdTokenContent> result = tokenBuilder.createIdToken(decodedJwt);

            // Then
            assertTrue(result.isPresent(), "Should return IdTokenContent");
            IdTokenContent idTokenContent = result.get();

            // Verify token type
            assertEquals(TokenType.ID_TOKEN, idTokenContent.getTokenType(), "Token type should be ID_TOKEN");

            // Verify raw token
            assertEquals(decodedJwt.getRawToken(), idTokenContent.getRawToken(), "Raw token should match");

            // Verify claims are extracted
            assertFalse(idTokenContent.getClaims().isEmpty(), "Claims should not be empty");
            assertTrue(idTokenContent.getClaims().containsKey(ClaimName.SUBJECT.getName()),
                    "Claims should contain subject");
            assertTrue(idTokenContent.getClaims().containsKey(ClaimName.ISSUER.getName()),
                    "Claims should contain issuer");
            assertTrue(idTokenContent.getClaims().containsKey(ClaimName.AUDIENCE.getName()),
                    "Claims should contain audience");
        }

        @Test
        @DisplayName("createIdToken should handle DecodedJwt with missing body")
        void createIdTokenShouldHandleDecodedJwtWithMissingBody() {
            // Given a DecodedJwt with null body
            DecodedJwt decodedJwt = new DecodedJwt(null, null, null, new String[]{"", "", ""}, "test-token");

            // When creating an IdTokenContent
            Optional<IdTokenContent> result = tokenBuilder.createIdToken(decodedJwt);

            // Then
            assertTrue(result.isEmpty(), "Should return empty Optional when body is missing");
        }
    }
}
