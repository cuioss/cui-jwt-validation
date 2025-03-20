package de.cuioss.jwt.token.test.generator;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import de.cuioss.jwt.token.JwtParser;
import de.cuioss.jwt.token.ParsedAccessToken;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Tests for the TokenGenerators factory and the generators it provides.
 */
class TokenGeneratorsTest {

    @Test
    @DisplayName("Should generate valid access tokens")
    void shouldGenerateValidAccessTokens() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.accessTokens();
        JwtParser parser = TestTokenProducer.getDefaultTokenParser();

        // When
        String token = generator.next();

        // Then
        assertNotNull(token, "Token should not be null");
        var parsedToken = ParsedAccessToken.fromTokenString(token, parser);
        assertTrue(parsedToken.isPresent(), "Token should be parseable");
    }

    @Test
    @DisplayName("Should generate valid ID tokens")
    void shouldGenerateValidIdTokens() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.idTokens();
        JwtParser parser = TestTokenProducer.getDefaultTokenParser();

        // When
        String token = generator.next();

        // Then
        assertNotNull(token, "Token should not be null");
        var parsedToken = ParsedAccessToken.fromTokenString(token, parser);
        assertTrue(parsedToken.isPresent(), "Token should be parseable");
    }

    @Test
    @DisplayName("Should generate valid refresh tokens")
    void shouldGenerateValidRefreshTokens() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.refreshTokens();
        JwtParser parser = TestTokenProducer.getDefaultTokenParser();

        // When
        String token = generator.next();

        // Then
        assertNotNull(token, "Token should not be null");
        var parsedToken = ParsedAccessToken.fromTokenString(token, parser);
        assertTrue(parsedToken.isPresent(), "Token should be parseable");
    }

    @Test
    @DisplayName("Should generate valid JWKS")
    void shouldGenerateValidJwks() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.jwks();

        // When
        String jwks = generator.next();

        // Then
        assertNotNull(jwks, "JWKS should not be null");
        assertTrue(jwks.contains("\"keys\""), "JWKS should contain keys array");
        assertTrue(jwks.contains("\"kty\":\"RSA\""), "JWKS should contain RSA key type");
    }

    @Test
    @DisplayName("Should generate valid scopes")
    void shouldGenerateValidScopes() {
        // Given
        TypedGenerator<String> generator = TokenGenerators.scopes();

        // When
        String scopes = generator.next();

        // Then
        assertNotNull(scopes, "Scopes should not be null");
        assertTrue(scopes.contains("openid"), "Scopes should contain openid");
    }

    @Test
    @DisplayName("Should generate valid roles")
    void shouldGenerateValidRoles() {
        // Given
        TypedGenerator<Set<String>> generator = TokenGenerators.roles();

        // When
        Set<String> roles = generator.next();

        // Then
        assertNotNull(roles, "Roles should not be null");
        assertTrue(roles.size() > 0, "Roles should not be empty");
    }

    @Test
    @DisplayName("Should generate valid groups")
    void shouldGenerateValidGroups() {
        // Given
        TypedGenerator<Set<String>> generator = TokenGenerators.groups();

        // When
        Set<String> groups = generator.next();

        // Then
        assertNotNull(groups, "Groups should not be null");
        assertTrue(groups.size() > 0, "Groups should not be empty");
    }

    @Test
    @DisplayName("Should generate valid alternative tokens")
    void shouldGenerateValidAlternativeTokens() {
        // Given
        TypedGenerator<String> accessTokenGenerator = TokenGenerators.alternativeAccessTokens();
        TypedGenerator<String> idTokenGenerator = TokenGenerators.alternativeIdTokens();
        TypedGenerator<String> refreshTokenGenerator = TokenGenerators.alternativeRefreshTokens();
        TypedGenerator<String> jwksGenerator = TokenGenerators.alternativeJwks();
        JwtParser parser = TestTokenProducer.getDefaultTokenParser();

        // When
        String accessToken = accessTokenGenerator.next();
        String idToken = idTokenGenerator.next();
        String refreshToken = refreshTokenGenerator.next();
        String jwks = jwksGenerator.next();

        // Then
        assertNotNull(accessToken, "Access token should not be null");
        assertNotNull(idToken, "ID token should not be null");
        assertNotNull(refreshToken, "Refresh token should not be null");
        assertNotNull(jwks, "JWKS should not be null");

        // Verify tokens are parseable
        assertTrue(ParsedAccessToken.fromTokenString(accessToken, parser).isPresent(), "Access token should be parseable");
        assertTrue(ParsedAccessToken.fromTokenString(idToken, parser).isPresent(), "ID token should be parseable");
        assertTrue(ParsedAccessToken.fromTokenString(refreshToken, parser).isPresent(), "Refresh token should be parseable");

        // Verify JWKS contains alternative key ID
        assertTrue(jwks.contains("test-key-id"), "JWKS should contain alternative key ID");
    }
}