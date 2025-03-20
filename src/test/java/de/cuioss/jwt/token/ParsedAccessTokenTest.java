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

import de.cuioss.jwt.token.test.TestJwtParser;
import de.cuioss.jwt.token.test.generator.TokenGenerators;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.domain.EmailGenerator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static de.cuioss.jwt.token.test.TestTokenProducer.SOME_NAME;
import static de.cuioss.jwt.token.test.TestTokenProducer.SOME_ROLES;
import static de.cuioss.jwt.token.test.TestTokenProducer.SOME_SCOPES;
import static de.cuioss.jwt.token.test.TestTokenProducer.getDefaultTokenParser;
import static de.cuioss.jwt.token.test.TestTokenProducer.validSignedEmptyJWT;
import static de.cuioss.jwt.token.test.TestTokenProducer.validSignedJWTWithClaims;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@DisplayName("Tests ParsedAccessToken functionality")
class ParsedAccessTokenTest {

    private static final String TEST_CONTEXT = "Test";
    private static final String EXISTING_SCOPE = "email";
    private static final String DEFINITELY_NO_SCOPE = "Definitely No Scope";
    private static final CuiLogger LOGGER = new CuiLogger(ParsedAccessTokenTest.class);

    @Nested
    @DisplayName("Token Scope Tests")
    class TokenScopeTests {

        @Test
        @DisplayName("Should correctly parse and validate token scopes")
        void shouldParseValidToken() {
            // Use TokenGenerators to generate an access token
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();
            var retrievedToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());

            assertTrue(retrievedToken.isPresent(), "Token should be present");
            var parsedAccessToken = retrievedToken.get();

            assertEquals(initialToken, parsedAccessToken.getTokenString(), "Token string should match");
            assertTrue(parsedAccessToken.getScopes().size() > 0, "Should have scopes");
            assertTrue(parsedAccessToken.getScopes().contains("openid"), "Should contain openid scope");
            assertFalse(parsedAccessToken.getScopes().contains(DEFINITELY_NO_SCOPE), "Should not contain invalid scope");

            assertTrue(parsedAccessToken.providesScopes(Set.of("openid")),
                    "Should provide openid scope");
            assertFalse(parsedAccessToken.providesScopes(Set.of(DEFINITELY_NO_SCOPE)),
                    "Should not provide non-existent scope");
            assertFalse(parsedAccessToken.providesScopes(Set.of(DEFINITELY_NO_SCOPE, "openid")),
                    "Should not provide mixed scopes when one is invalid");

            assertTrue(parsedAccessToken.providesScopesAndDebugIfScopesAreMissing(
                            Set.of("openid"), TEST_CONTEXT, LOGGER),
                    "Should provide scope with debug logging");
            assertFalse(parsedAccessToken.providesScopesAndDebugIfScopesAreMissing(
                            Set.of("openid", DEFINITELY_NO_SCOPE), TEST_CONTEXT, LOGGER),
                    "Should not provide scopes with debug logging when one is invalid");

            Set<String> missingScopes = parsedAccessToken.determineMissingScopes(Set.of("openid"));
            assertTrue(missingScopes.isEmpty(), "Should have no missing scopes for valid scope");

            missingScopes = parsedAccessToken.determineMissingScopes(Set.of(DEFINITELY_NO_SCOPE));
            assertEquals(1, missingScopes.size(), "Should have one missing scope");
            assertTrue(missingScopes.contains(DEFINITELY_NO_SCOPE), "Should contain invalid scope as missing");

            missingScopes = parsedAccessToken.determineMissingScopes(Set.of("openid", DEFINITELY_NO_SCOPE));
            assertEquals(1, missingScopes.size(), "Should have one missing scope in mixed set");
            assertTrue(missingScopes.contains(DEFINITELY_NO_SCOPE), "Should contain invalid scope as missing in mixed set");
        }

        @Test
        @DisplayName("Should handle token without scopes")
        void shouldHandleMissingScopes() {
            // For this test, we still need a token without scopes, so we'll keep using validSignedEmptyJWT
            String initialToken = validSignedEmptyJWT();
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertTrue(parsedAccessToken.get().getScopes().isEmpty(), "Scopes should be empty");
        }
    }

    @Nested
    @DisplayName("Token Role Tests")
    class TokenRoleTests {

        @Test
        @DisplayName("Should handle token with roles")
        void shouldHandleGivenRoles() {
            // Use TokenGenerators to generate an access token with roles
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());

            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            // Since we don't know which roles are in the token, we'll check that there are roles
            assertFalse(parsedAccessToken.get().getRoles().isEmpty(), "Should have roles");

            // Check that at least one role exists
            String someRole = parsedAccessToken.get().getRoles().iterator().next();
            assertTrue(parsedAccessToken.get().hasRole(someRole), "Should have the role: " + someRole);
        }

        @Test
        @DisplayName("Should handle non-existent roles")
        void shouldHandleMissingRoles() {
            // Use TokenGenerators to generate an access token with roles
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());

            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertFalse(parsedAccessToken.get().hasRole(DEFINITELY_NO_SCOPE), "Should not have non-existent role");
        }

        @Test
        @DisplayName("Should handle token without roles")
        void shouldHandleNoRoles() {
            TestJwtParser.setCurrentTestMethod("shouldHandleNoRoles");
            // For this test, we need a token without roles, so we'll keep using validSignedJWTWithClaims(SOME_SCOPES)
            // The AccessTokenGenerator always includes roles, so we can't use it here
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);
            System.out.println("[DEBUG_LOG] Token for shouldHandleNoRoles: " + initialToken);
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            System.out.println("[DEBUG_LOG] Roles: " + parsedAccessToken.get().getRoles());
            System.out.println("[DEBUG_LOG] Roles isEmpty: " + parsedAccessToken.get().getRoles().isEmpty());
            assertTrue(parsedAccessToken.get().getRoles().isEmpty(), "Roles should be empty");
        }

        @Test
        @DisplayName("Should correctly determine missing roles")
        void shouldDetermineMissingRoles() {
            // Use TokenGenerators to generate an access token with roles
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());

            assertTrue(parsedAccessToken.isPresent(), "Token should be present");

            // Get a role from the token to test with
            String someRole = parsedAccessToken.get().getRoles().iterator().next();

            // Test with existing role
            Set<String> missingRoles = parsedAccessToken.get().determineMissingRoles(Set.of(someRole));
            assertTrue(missingRoles.isEmpty(), "Should have no missing roles for valid role: " + someRole);

            // Test with non-existent role
            missingRoles = parsedAccessToken.get().determineMissingRoles(Set.of(DEFINITELY_NO_SCOPE));
            assertEquals(1, missingRoles.size(), "Should have one missing role");
            assertTrue(missingRoles.contains(DEFINITELY_NO_SCOPE), "Should contain invalid role as missing");

            // Test with mixed roles (existing and non-existing)
            missingRoles = parsedAccessToken.get().determineMissingRoles(Set.of(someRole, DEFINITELY_NO_SCOPE));
            assertEquals(1, missingRoles.size(), "Should have one missing role in mixed set");
            assertTrue(missingRoles.contains(DEFINITELY_NO_SCOPE), "Should contain invalid role as missing in mixed set");
        }

        @Test
        @DisplayName("Should handle null or empty expected roles")
        void shouldHandleNullOrEmptyExpectedRoles() {
            // Use TokenGenerators to generate an access token with roles
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());

            assertTrue(parsedAccessToken.isPresent(), "Token should be present");

            // Test with null roles
            Set<String> missingRoles = parsedAccessToken.get().determineMissingRoles(null);
            assertTrue(missingRoles.isEmpty(), "Should return empty set for null expected roles");

            // Test with empty roles
            missingRoles = parsedAccessToken.get().determineMissingRoles(Set.of());
            assertTrue(missingRoles.isEmpty(), "Should return empty set for empty expected roles");
        }
    }

    @Nested
    @DisplayName("Token Subject Tests")
    class TokenSubjectTests {

        @Test
        @DisplayName("Should handle token with subject ID")
        void shouldHandleSubjectId() {
            // Use TokenGenerators to generate an access token
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertNotNull(parsedAccessToken.get().getSubjectId(), "Subject ID should not be null");
            assertFalse(parsedAccessToken.get().getSubjectId().isEmpty(), "Subject ID should not be empty");
        }
    }

    @Nested
    @DisplayName("Token Email Tests")
    class TokenEmailTests {

        @Test
        @DisplayName("Should handle token with email")
        void shouldHandleGivenEmail() {
            // Use TokenGenerators to generate an access token
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();

            // The token already has an email, but we'll override it with a custom one
            String expectedEmail = new EmailGenerator().next();

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, expectedEmail, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertEquals(expectedEmail, parsedAccessToken.get().getEmail().get(), "Email should match");
        }

        @Test
        @DisplayName("Should handle token without email")
        void shouldHandleMissingEmail() {
            // Use TokenGenerators to generate an access token
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();

            // We're not providing an email to fromTokenString, so it should use the one from the token
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertTrue(parsedAccessToken.get().getEmail().isPresent(), "Email should be present");
            assertNotNull(parsedAccessToken.get().getEmail().get(), "Email should not be null");
        }
    }

    @Nested
    @DisplayName("Token Name Tests")
    class TokenNameTests {

        @Test
        @DisplayName("Should handle token with name")
        void shouldHandleGivenName() {
            // Use TokenGenerators to generate an ID token
            TypedGenerator<String> idTokenGenerator = TokenGenerators.idTokens();
            String initialToken = idTokenGenerator.next();

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertTrue(parsedAccessToken.get().getName().isPresent(), "Name should be present");
            assertNotNull(parsedAccessToken.get().getName().get(), "Name should not be null");
        }

        @Test
        @DisplayName("Should handle token without name")
        void shouldHandleMissingName() {
            // Use TokenGenerators to generate an access token (which doesn't have a name)
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertFalse(parsedAccessToken.get().getName().isPresent(), "Name should not be present");
        }

        @Test
        @DisplayName("Should handle token with preferred username")
        void shouldHandlePreferredName() {
            // Use TokenGenerators to generate an ID token
            TypedGenerator<String> idTokenGenerator = TokenGenerators.idTokens();
            String initialToken = idTokenGenerator.next();

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertTrue(parsedAccessToken.get().getPreferredUsername().isPresent(), "Preferred username should be present");
            assertNotNull(parsedAccessToken.get().getPreferredUsername().get(), "Preferred username should not be null");
        }

        @Test
        @DisplayName("Should handle token without preferred username")
        void shouldHandleMissingPreferredName() {
            // Use TokenGenerators to generate an access token (which doesn't have a preferred username)
            TypedGenerator<String> accessTokenGenerator = TokenGenerators.accessTokens();
            String initialToken = accessTokenGenerator.next();

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertFalse(parsedAccessToken.get().getPreferredUsername().isPresent(),
                    "Preferred username should not be present");
        }
    }
}
