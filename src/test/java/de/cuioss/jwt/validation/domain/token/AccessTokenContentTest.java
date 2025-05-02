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
package de.cuioss.jwt.validation.domain.token;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.test.TestTokenProducer;
import de.cuioss.jwt.validation.test.generator.ScopeGenerator;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link AccessTokenContent}.
 */
@DisplayName("Tests AccessTokenContent functionality")
class AccessTokenContentTest {

    private static final CuiLogger LOGGER = new CuiLogger(AccessTokenContentTest.class);
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
        assertEquals(rawToken, accessTokenContent.getRawToken(), "Raw validation should match");
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

    @Test
    @DisplayName("Should return true when validation provides all expected scopes")
    void shouldReturnTrueWhenTokenProvidesAllExpectedScopes() {
        // Given an AccessTokenContent with scopes
        ScopeGenerator scopeGenerator = new ScopeGenerator(3, 5);
        String scopeString = scopeGenerator.next();
        Collection<String> allScopes = ScopeGenerator.splitScopes(scopeString);

        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.SCOPE.getName(), ClaimValue.forList(allScopes.toString(), new ArrayList<>(allScopes)));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When checking if validation provides a subset of scopes
        List<String> expectedScopes = new ArrayList<>(allScopes);
        if (expectedScopes.size() > 1) {
            expectedScopes = expectedScopes.subList(0, expectedScopes.size() - 1);
        }
        boolean result = accessTokenContent.providesScopes(expectedScopes);

        // Then the result should be true
        assertTrue(result, "Token should provide all expected scopes");
    }

    @Test
    @DisplayName("Should return false when validation does not provide all expected scopes")
    void shouldReturnFalseWhenTokenDoesNotProvideAllExpectedScopes() {
        // Given an AccessTokenContent with scopes
        ScopeGenerator scopeGenerator = new ScopeGenerator(2, 4);
        String scopeString = scopeGenerator.next();
        Collection<String> scopes = ScopeGenerator.splitScopes(scopeString);

        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.SCOPE.getName(), ClaimValue.forList(scopes.toString(), new ArrayList<>(scopes)));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When checking if validation provides scopes including one that's not in the validation
        List<String> expectedScopes = new ArrayList<>(scopes);
        expectedScopes.add("non_existent_scope");
        boolean result = accessTokenContent.providesScopes(expectedScopes);

        // Then the result should be false
        assertFalse(result, "Token should not provide all expected scopes");
    }

    @Test
    @DisplayName("Should return true when no expected scopes are provided")
    void shouldReturnTrueWhenNoExpectedScopesAreProvided() {
        // Given an AccessTokenContent with scopes
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.SCOPE.getName(), ClaimValue.forList(TEST_SCOPES.toString(), TEST_SCOPES));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When checking if validation provides empty list of scopes
        boolean result = accessTokenContent.providesScopes(Collections.emptyList());

        // Then the result should be true
        assertTrue(result, "Token should provide all expected scopes when none are expected");
    }

    @Test
    @DisplayName("Should return true when validation provides all expected scopes with debug logging")
    void shouldReturnTrueWhenTokenProvidesAllExpectedScopesWithDebugLogging() {
        // Given an AccessTokenContent with scopes
        ScopeGenerator scopeGenerator = new ScopeGenerator(3, 5);
        String scopeString = scopeGenerator.next();
        Collection<String> allScopes = ScopeGenerator.splitScopes(scopeString);

        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.SCOPE.getName(), ClaimValue.forList(allScopes.toString(), new ArrayList<>(allScopes)));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When checking if validation provides a subset of scopes with debug logging
        List<String> expectedScopes = new ArrayList<>(allScopes);
        if (expectedScopes.size() > 1) {
            expectedScopes = expectedScopes.subList(0, expectedScopes.size() - 1);
        }
        boolean result = accessTokenContent.providesScopesAndDebugIfScopesAreMissing(
                expectedScopes, "Test context", LOGGER);

        // Then the result should be true
        assertTrue(result, "Token should provide all expected scopes");
    }

    @Test
    @DisplayName("Should return false when validation does not provide all expected scopes with debug logging")
    void shouldReturnFalseWhenTokenDoesNotProvideAllExpectedScopesWithDebugLogging() {
        // Given an AccessTokenContent with scopes
        ScopeGenerator scopeGenerator = new ScopeGenerator(2, 4);
        String scopeString = scopeGenerator.next();
        Collection<String> scopes = ScopeGenerator.splitScopes(scopeString);

        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.SCOPE.getName(), ClaimValue.forList(scopes.toString(), new ArrayList<>(scopes)));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When checking if validation provides scopes including one that's not in the validation with debug logging
        List<String> expectedScopes = new ArrayList<>(scopes);
        expectedScopes.add("non_existent_scope");
        boolean result = accessTokenContent.providesScopesAndDebugIfScopesAreMissing(
                expectedScopes, "Test context", LOGGER);

        // Then the result should be false
        assertFalse(result, "Token should not provide all expected scopes");
    }

    @Test
    @DisplayName("Should return empty set when validation provides all expected scopes")
    void shouldReturnEmptySetWhenTokenProvidesAllExpectedScopes() {
        // Given an AccessTokenContent with scopes
        ScopeGenerator scopeGenerator = new ScopeGenerator(3, 5);
        String scopeString = scopeGenerator.next();
        Collection<String> allScopes = ScopeGenerator.splitScopes(scopeString);

        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.SCOPE.getName(), ClaimValue.forList(allScopes.toString(), new ArrayList<>(allScopes)));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When determining missing scopes for a subset of the validation's scopes
        List<String> expectedScopes = new ArrayList<>(allScopes);
        if (expectedScopes.size() > 1) {
            expectedScopes = expectedScopes.subList(0, expectedScopes.size() - 1);
        }
        Set<String> missingScopes = accessTokenContent.determineMissingScopes(expectedScopes);

        // Then the result should be an empty set
        assertTrue(missingScopes.isEmpty(), "There should be no missing scopes");
    }

    @Test
    @DisplayName("Should return set of missing scopes when validation does not provide all expected scopes")
    void shouldReturnSetOfMissingScopesWhenTokenDoesNotProvideAllExpectedScopes() {
        // Given an AccessTokenContent with scopes
        ScopeGenerator scopeGenerator = new ScopeGenerator(2, 4);
        String scopeString = scopeGenerator.next();
        Collection<String> scopes = ScopeGenerator.splitScopes(scopeString);

        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.SCOPE.getName(), ClaimValue.forList(scopes.toString(), new ArrayList<>(scopes)));
        var accessTokenContent = new AccessTokenContent(claims, SAMPLE_TOKEN, TEST_EMAIL);

        // When determining missing scopes including ones that are not in the validation
        List<String> expectedScopes = new ArrayList<>(scopes);
        String missingScope1 = "non_existent_scope1";
        String missingScope2 = "non_existent_scope2";
        expectedScopes.add(missingScope1);
        expectedScopes.add(missingScope2);
        Set<String> missingScopes = accessTokenContent.determineMissingScopes(expectedScopes);

        // Then the result should contain the missing scopes
        assertEquals(2, missingScopes.size(), "There should be exactly 2 missing scopes");
        assertTrue(missingScopes.contains(missingScope1), "Missing scopes should contain " + missingScope1);
        assertTrue(missingScopes.contains(missingScope2), "Missing scopes should contain " + missingScope2);
    }
}
