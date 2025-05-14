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
package de.cuioss.jwt.validation.test.generator;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.token.TokenContent;
import de.cuioss.test.generator.TypedGenerator;

import java.util.Set;

/**
 * Factory for unified access to token generators.
 * Provides access to generators for various token types and JWKS.
 * Includes variants for "default" or "alternative" mode.
 * <p>
 * This factory also provides methods for converting between TokenContent objects
 * and JWT strings using the {@link TokenContentToJwtConverter}.
 */
public class TokenGenerators {

    private TokenGenerators() {
        // Private constructor to prevent instantiation
    }

    /**
     * Gets a generator for access tokens in default mode.
     *
     * @return a generator for access tokens
     */
    public static TypedGenerator<String> accessTokens() {
        return new AccessTokenGenerator(false);
    }

    /**
     * Gets a generator for access tokens in alternative mode.
     *
     * @return a generator for access tokens
     */
    public static TypedGenerator<String> alternativeAccessTokens() {
        return new AccessTokenGenerator(true);
    }

    /**
     * Gets a generator for ID tokens in default mode.
     *
     * @return a generator for ID tokens
     */
    public static TypedGenerator<String> idTokens() {
        return new IDTokenGenerator(false);
    }

    /**
     * Gets a generator for ID tokens in alternative mode.
     *
     * @return a generator for ID tokens
     */
    public static TypedGenerator<String> alternativeIdTokens() {
        return new IDTokenGenerator(true);
    }

    /**
     * Gets a generator for refresh tokens in default mode.
     *
     * @return a generator for refresh tokens
     */
    public static TypedGenerator<String> refreshTokens() {
        return new RefreshTokenGenerator(false);
    }

    /**
     * Gets a generator for refresh tokens in alternative mode.
     *
     * @return a generator for refresh tokens
     */
    public static TypedGenerator<String> alternativeRefreshTokens() {
        return new RefreshTokenGenerator(true);
    }

    /**
     * Gets a generator for JWKS in default mode.
     *
     * @return a generator for JWKS
     */
    public static TypedGenerator<String> jwks() {
        return new JWKSGenerator(false);
    }

    /**
     * Gets a generator for JWKS in alternative mode.
     *
     * @return a generator for JWKS
     */
    public static TypedGenerator<String> alternativeJwks() {
        return new JWKSGenerator(true);
    }

    /**
     * Gets a generator for scopes.
     *
     * @return a generator for scopes
     */
    public static TypedGenerator<String> scopes() {
        return new ScopeGenerator();
    }

    /**
     * Gets a generator for roles.
     *
     * @return a generator for roles
     */
    public static TypedGenerator<Set<String>> roles() {
        return new RoleGenerator();
    }

    /**
     * Gets a generator for groups.
     *
     * @return a generator for groups
     */
    public static TypedGenerator<Set<String>> groups() {
        return new GroupGenerator();
    }

    /**
     * Gets a generator for valid token content with default token type (ACCESS_TOKEN).
     *
     * @return a generator for valid token content
     */
    public static TypedGenerator<TokenContentImpl> validTokenContent() {
        return new ValidTokenContentGenerator();
    }

    /**
     * Gets a generator for valid token content with the specified token type.
     *
     * @param tokenType the type of token to generate
     * @return a generator for valid token content
     */
    public static TypedGenerator<TokenContentImpl> validTokenContent(TokenType tokenType) {
        return new ValidTokenContentGenerator(tokenType);
    }

    /**
     * Gets a generator for valid access token content.
     *
     * @return a generator for valid access token content
     */
    public static TypedGenerator<TokenContentImpl> validAccessTokenContent() {
        return validTokenContent(TokenType.ACCESS_TOKEN);
    }

    /**
     * Gets a generator for valid ID token content.
     *
     * @return a generator for valid ID token content
     */
    public static TypedGenerator<TokenContentImpl> validIdTokenContent() {
        return validTokenContent(TokenType.ID_TOKEN);
    }

    /**
     * Gets a generator for valid refresh token content.
     *
     * @return a generator for valid refresh token content
     */
    public static TypedGenerator<TokenContentImpl> validRefreshTokenContent() {
        return validTokenContent(TokenType.REFRESH_TOKEN);
    }

    /**
     * Gets a generator for invalid token content with default token type (ACCESS_TOKEN).
     *
     * @return a generator for invalid token content
     */
    public static InvalidTokenContentGenerator invalidTokenContent() {
        return new InvalidTokenContentGenerator();
    }

    /**
     * Gets a generator for invalid token content with the specified token type.
     *
     * @param tokenType the type of token to generate
     * @return a generator for invalid token content
     */
    public static InvalidTokenContentGenerator invalidTokenContent(TokenType tokenType) {
        return new InvalidTokenContentGenerator(tokenType);
    }

    /**
     * Gets a generator for invalid access token content.
     *
     * @return a generator for invalid access token content
     */
    public static InvalidTokenContentGenerator invalidAccessTokenContent() {
        return invalidTokenContent(TokenType.ACCESS_TOKEN);
    }

    /**
     * Gets a generator for invalid ID token content.
     *
     * @return a generator for invalid ID token content
     */
    public static InvalidTokenContentGenerator invalidIdTokenContent() {
        return invalidTokenContent(TokenType.ID_TOKEN);
    }

    /**
     * Gets a generator for invalid refresh token content.
     *
     * @return a generator for invalid refresh token content
     */
    public static InvalidTokenContentGenerator invalidRefreshTokenContent() {
        return invalidTokenContent(TokenType.REFRESH_TOKEN);
    }

    /**
     * Gets a generator for token content with missing issuer.
     *
     * @return a generator for token content with missing issuer
     */
    public static InvalidTokenContentGenerator invalidTokenContentWithMissingIssuer() {
        return invalidTokenContent().withMissingIssuer();
    }

    /**
     * Gets a generator for token content with missing subject.
     *
     * @return a generator for token content with missing subject
     */
    public static InvalidTokenContentGenerator invalidTokenContentWithMissingSubject() {
        return invalidTokenContent().withMissingSubject();
    }

    /**
     * Gets a generator for token content with missing expiration.
     *
     * @return a generator for token content with missing expiration
     */
    public static InvalidTokenContentGenerator invalidTokenContentWithMissingExpiration() {
        return invalidTokenContent().withMissingExpiration();
    }

    /**
     * Gets a generator for expired token content.
     *
     * @return a generator for expired token content
     */
    public static InvalidTokenContentGenerator invalidTokenContentWithExpiredToken() {
        return invalidTokenContent().withExpiredToken();
    }

    /**
     * Gets a generator for token content with missing issuedAt.
     *
     * @return a generator for token content with missing issuedAt
     */
    public static InvalidTokenContentGenerator invalidTokenContentWithMissingIssuedAt() {
        return invalidTokenContent().withMissingIssuedAt();
    }

    /**
     * Gets a generator for token content with missing token type.
     *
     * @return a generator for token content with missing token type
     */
    public static InvalidTokenContentGenerator invalidTokenContentWithMissingTokenType() {
        return invalidTokenContent().withMissingTokenType();
    }

    /**
     * Gets a generator for token content with missing scope.
     *
     * @return a generator for token content with missing scope
     */
    public static InvalidTokenContentGenerator invalidTokenContentWithMissingScope() {
        return invalidTokenContent().withMissingScope();
    }

    /**
     * Gets a generator for token content with missing audience.
     *
     * @return a generator for token content with missing audience
     */
    public static InvalidTokenContentGenerator invalidTokenContentWithMissingAudience() {
        return invalidTokenContent().withMissingAudience();
    }

    /**
     * Gets a generator for token content with missing authorized party.
     *
     * @return a generator for token content with missing authorized party
     */
    public static InvalidTokenContentGenerator invalidTokenContentWithMissingAuthorizedParty() {
        return invalidTokenContent().withMissingAuthorizedParty();
    }

    /**
     * Converts a TokenContent object to a JWT string.
     * <p>
     * This method uses the {@link TokenContentToJwtConverter} to convert a TokenContent
     * object to a properly signed JWT string.
     *
     * @param tokenContent the TokenContent to convert
     * @return a JWT string representation of the TokenContent
     * @throws IllegalArgumentException if the TokenContent is null
     */
    public static String toJwtString(TokenContent tokenContent) {
        return TokenContentToJwtConverter.toJwtString(tokenContent);
    }

    /**
     * Creates a TokenContent object from a JWT string.
     * <p>
     * This method uses the {@link TokenContentToJwtConverter} to parse a JWT string
     * into a TokenContent object.
     *
     * @param jwtString the JWT string to parse
     * @return a TokenContent representation of the JWT string
     * @throws IllegalArgumentException if the JWT string is null or empty
     */
    public static TokenContent fromJwtString(String jwtString) {
        return TokenContentToJwtConverter.fromJwtString(jwtString);
    }

    /**
     * Generates a JWT string from a valid TokenContent of the specified type.
     * <p>
     * This method combines the functionality of {@link #validTokenContent(TokenType)}
     * and {@link #toJwtString(TokenContent)} to generate a JWT string directly.
     *
     * @param tokenType the type of token to generate
     * @return a JWT string of the specified type
     */
    public static String jwtStringFromTokenContent(TokenType tokenType) {
        TokenContent tokenContent = validTokenContent(tokenType).next();
        return toJwtString(tokenContent);
    }
}
