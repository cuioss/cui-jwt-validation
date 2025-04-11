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
package de.cuioss.jwt.token.domain.token;

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.claim.ClaimName;
import de.cuioss.jwt.token.domain.claim.ClaimValue;
import de.cuioss.jwt.token.test.TestTokenProducer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link AccessTokenContent}.
 */
@DisplayName("Tests AccessTokenContent functionality")
class AccessTokenContentTest {

    private static final String SAMPLE_TOKEN = TestTokenProducer.validSignedEmptyJWT();
    private static final String TEST_EMAIL = "test@example.com";
    private static final List<String> TEST_SCOPES = Arrays.asList("openid", "profile", "email");
    private static final List<String> TEST_AUDIENCE = Arrays.asList("client1", "client2");

    @Test
    @DisplayName("Should create AccessTokenContent with valid parameters")
    void shouldCreateAccessTokenContentWithValidParameters() {
        // Given valid parameters
        Map<String, ClaimValue> claims = new HashMap<>();
        String rawToken = SAMPLE_TOKEN;
        String email = TEST_EMAIL;

        // When creating an AccessTokenContent
        var accessTokenContent = new AccessTokenContent(claims, rawToken, email);

        // Then the content should be correctly initialized
        assertNotNull(accessTokenContent, "AccessTokenContent should not be null");
        assertEquals(claims, accessTokenContent.getClaims(), "Claims should match");
        assertEquals(rawToken, accessTokenContent.getRawToken(), "Raw token should match");
        assertEquals(TokenType.ACCESS_TOKEN, accessTokenContent.getTokenType(), "Token type should be ACCESS_TOKEN");
        assertEquals(Optional.of(email), accessTokenContent.getEmail(), "Email should match");
    }

    @Test
    @DisplayName("Should return audience correctly when present")
    void shouldReturnAudienceCorrectlyWhenPresent() {
        // Given an AccessTokenContent with audience claim
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.AUDIENCE.getName(), ClaimValue.forList(TEST_AUDIENCE.toString(), TEST_AUDIENCE));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When getting the audience
        Optional<List<String>> audience = accessTokenContent.getAudience();

        // Then the audience should be present and contain the correct values
        assertTrue(audience.isPresent(), "Audience should be present");
        assertEquals(TEST_AUDIENCE, audience.get(), "Audience should match");
    }

    @Test
    @DisplayName("Should return empty audience when not present")
    void shouldReturnEmptyAudienceWhenNotPresent() {
        // Given an AccessTokenContent without audience claim
        Map<String, ClaimValue> claims = new HashMap<>();
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When getting the audience
        Optional<List<String>> audience = accessTokenContent.getAudience();

        // Then the audience should be empty
        assertTrue(audience.isEmpty(), "Audience should be empty");
    }

    @Test
    @DisplayName("Should return scopes correctly when present")
    void shouldReturnScopesCorrectlyWhenPresent() {
        // Given an AccessTokenContent with scope claim
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.SCOPE.getName(), ClaimValue.forList(TEST_SCOPES.toString(), TEST_SCOPES));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When getting the scopes
        List<String> scopes = accessTokenContent.getScopes();

        // Then the scopes should contain the correct values
        assertEquals(TEST_SCOPES, scopes, "Scopes should match");
    }

    @Test
    @DisplayName("Should throw exception when scopes not present")
    void shouldThrowExceptionWhenScopesNotPresent() {
        // Given an AccessTokenContent without scope claim
        Map<String, ClaimValue> claims = new HashMap<>();
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When getting the scopes
        // Then an exception should be thrown
        assertThrows(IllegalStateException.class, accessTokenContent::getScopes,
                "Should throw IllegalStateException for missing scope claim");
    }

    @Test
    @DisplayName("Should return email from constructor when provided")
    void shouldReturnEmailFromConstructorWhenProvided() {
        // Given an AccessTokenContent with email in constructor
        Map<String, ClaimValue> claims = new HashMap<>();
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When getting the email
        Optional<String> email = accessTokenContent.getEmail();

        // Then the email should be present and match the constructor value
        assertTrue(email.isPresent(), "Email should be present");
        assertEquals(TEST_EMAIL, email.get(), "Email should match constructor value");
    }

    @Test
    @DisplayName("Should return email from claims when not provided in constructor")
    void shouldReturnEmailFromClaimsWhenNotProvidedInConstructor() {
        // Given an AccessTokenContent with email in claims but not in constructor
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.EMAIL.getName(), ClaimValue.forPlainString(TEST_EMAIL));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, null);

        // When getting the email
        Optional<String> email = accessTokenContent.getEmail();

        // Then the email should be present and match the claim value
        assertTrue(email.isPresent(), "Email should be present");
        assertEquals(TEST_EMAIL, email.get(), "Email should match claim value");
    }

    @Test
    @DisplayName("Should return empty email when not provided anywhere")
    void shouldReturnEmptyEmailWhenNotProvidedAnywhere() {
        // Given an AccessTokenContent without email in constructor or claims
        Map<String, ClaimValue> claims = new HashMap<>();
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, null);

        // When getting the email
        Optional<String> email = accessTokenContent.getEmail();

        // Then the email should be empty
        assertTrue(email.isEmpty(), "Email should be empty");
    }

    @Test
    @DisplayName("Should return preferred username when present")
    void shouldReturnPreferredUsernameWhenPresent() {
        // Given an AccessTokenContent with preferred username claim
        Map<String, ClaimValue> claims = new HashMap<>();
        String username = "testuser";
        claims.put(ClaimName.PREFERRED_USERNAME.getName(), ClaimValue.forPlainString(username));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When getting the preferred username
        Optional<String> preferredUsername = accessTokenContent.getPreferredUsername();

        // Then the preferred username should be present and contain the correct value
        assertTrue(preferredUsername.isPresent(), "Preferred username should be present");
        assertEquals(username, preferredUsername.get(), "Preferred username should match");
    }

    @Test
    @DisplayName("Should return empty preferred username when not present")
    void shouldReturnEmptyPreferredUsernameWhenNotPresent() {
        // Given an AccessTokenContent without preferred username claim
        Map<String, ClaimValue> claims = new HashMap<>();
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When getting the preferred username
        Optional<String> preferredUsername = accessTokenContent.getPreferredUsername();

        // Then the preferred username should be empty
        assertTrue(preferredUsername.isEmpty(), "Preferred username should be empty");
    }

}
