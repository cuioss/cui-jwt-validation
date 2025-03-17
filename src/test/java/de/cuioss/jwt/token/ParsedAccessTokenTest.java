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
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.domain.EmailGenerator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static de.cuioss.jwt.token.test.TestTokenProducer.*;
import static org.junit.jupiter.api.Assertions.*;

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
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);
            var retrievedToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());

            assertTrue(retrievedToken.isPresent(), "Token should be present");
            var parsedAccessToken = retrievedToken.get();

            assertEquals(initialToken, parsedAccessToken.getTokenString(), "Token string should match");
            assertEquals(3, parsedAccessToken.getScopes().size(), "Should have 3 scopes");
            assertTrue(parsedAccessToken.getScopes().contains(EXISTING_SCOPE), "Should contain email scope");
            assertFalse(parsedAccessToken.getScopes().contains(DEFINITELY_NO_SCOPE), "Should not contain invalid scope");

            assertTrue(parsedAccessToken.providesScopes(Set.of(EXISTING_SCOPE)),
                    "Should provide existing scope");
            assertFalse(parsedAccessToken.providesScopes(Set.of(DEFINITELY_NO_SCOPE)),
                    "Should not provide non-existent scope");
            assertFalse(parsedAccessToken.providesScopes(Set.of(DEFINITELY_NO_SCOPE, EXISTING_SCOPE)),
                    "Should not provide mixed scopes when one is invalid");

            assertTrue(parsedAccessToken.providesScopesAndDebugIfScopesAreMissing(
                            Set.of(EXISTING_SCOPE), TEST_CONTEXT, LOGGER),
                    "Should provide scope with debug logging");
            assertFalse(parsedAccessToken.providesScopesAndDebugIfScopesAreMissing(
                            Set.of(EXISTING_SCOPE, DEFINITELY_NO_SCOPE), TEST_CONTEXT, LOGGER),
                    "Should not provide scopes with debug logging when one is invalid");

            Set<String> missingScopes = parsedAccessToken.determineMissingScopes(Set.of(EXISTING_SCOPE));
            assertTrue(missingScopes.isEmpty(), "Should have no missing scopes for valid scope");

            missingScopes = parsedAccessToken.determineMissingScopes(Set.of(DEFINITELY_NO_SCOPE));
            assertEquals(1, missingScopes.size(), "Should have one missing scope");
            assertTrue(missingScopes.contains(DEFINITELY_NO_SCOPE), "Should contain invalid scope as missing");

            missingScopes = parsedAccessToken.determineMissingScopes(Set.of(EXISTING_SCOPE, DEFINITELY_NO_SCOPE));
            assertEquals(1, missingScopes.size(), "Should have one missing scope in mixed set");
            assertTrue(missingScopes.contains(DEFINITELY_NO_SCOPE), "Should contain invalid scope as missing in mixed set");
        }

        @Test
        @DisplayName("Should handle token without scopes")
        void shouldHandleMissingScopes() {
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
            String initialToken = validSignedJWTWithClaims(SOME_ROLES);
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertTrue(parsedAccessToken.get().hasRole("reader"), "Should have reader role");
        }

        @Test
        @DisplayName("Should handle non-existent roles")
        void shouldHandleMissingRoles() {
            String initialToken = validSignedJWTWithClaims(SOME_ROLES);
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertFalse(parsedAccessToken.get().hasRole(DEFINITELY_NO_SCOPE), "Should not have non-existent role");
        }

        @Test
        @DisplayName("Should handle token without roles")
        void shouldHandleNoRoles() {
            TestJwtParser.setCurrentTestMethod("shouldHandleNoRoles");
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
            String initialToken = validSignedJWTWithClaims(SOME_ROLES);
            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");

            // Test with existing role
            Set<String> missingRoles = parsedAccessToken.get().determineMissingRoles(Set.of("reader"));
            assertTrue(missingRoles.isEmpty(), "Should have no missing roles for valid role");

            // Test with non-existent role
            missingRoles = parsedAccessToken.get().determineMissingRoles(Set.of(DEFINITELY_NO_SCOPE));
            assertEquals(1, missingRoles.size(), "Should have one missing role");
            assertTrue(missingRoles.contains(DEFINITELY_NO_SCOPE), "Should contain invalid role as missing");

            // Test with mixed roles (existing and non-existing)
            missingRoles = parsedAccessToken.get().determineMissingRoles(Set.of("reader", DEFINITELY_NO_SCOPE));
            assertEquals(1, missingRoles.size(), "Should have one missing role in mixed set");
            assertTrue(missingRoles.contains(DEFINITELY_NO_SCOPE), "Should contain invalid role as missing in mixed set");
        }

        @Test
        @DisplayName("Should handle null or empty expected roles")
        void shouldHandleNullOrEmptyExpectedRoles() {
            String initialToken = validSignedJWTWithClaims(SOME_ROLES);
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
            String expectedSubjectId = Generators.letterStrings(4, 9).next();
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES, expectedSubjectId);

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertEquals(expectedSubjectId, parsedAccessToken.get().getSubjectId(), "Subject ID should match");
        }
    }

    @Nested
    @DisplayName("Token Email Tests")
    class TokenEmailTests {

        @Test
        @DisplayName("Should handle token with email")
        void shouldHandleGivenEmail() {
            String expectedEmail = new EmailGenerator().next();
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, expectedEmail, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertEquals(expectedEmail, parsedAccessToken.get().getEmail().get(), "Email should match");
        }

        @Test
        @DisplayName("Should handle token without email")
        void shouldHandleMissingEmail() {
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertFalse(parsedAccessToken.get().getEmail().isPresent(), "Email should not be present");
        }
    }

    @Nested
    @DisplayName("Token Name Tests")
    class TokenNameTests {

        @Test
        @DisplayName("Should handle token with name")
        void shouldHandleGivenName() {
            String initialToken = validSignedJWTWithClaims(SOME_NAME);

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertEquals("hello", parsedAccessToken.get().getName().get(), "Name should match");
        }

        @Test
        @DisplayName("Should handle token without name")
        void shouldHandleMissingName() {
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertFalse(parsedAccessToken.get().getName().isPresent(), "Name should not be present");
        }

        @Test
        @DisplayName("Should handle token with preferred username")
        void shouldHandlePreferredName() {
            String initialToken = validSignedJWTWithClaims(SOME_NAME);

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertEquals("world", parsedAccessToken.get().getPreferredUsername().get(),
                    "Preferred username should match");
        }

        @Test
        @DisplayName("Should handle token without preferred username")
        void shouldHandleMissingPreferredName() {
            String initialToken = validSignedJWTWithClaims(SOME_SCOPES);

            var parsedAccessToken = ParsedAccessToken.fromTokenString(initialToken, getDefaultTokenParser());
            assertTrue(parsedAccessToken.isPresent(), "Token should be present");
            assertFalse(parsedAccessToken.get().getPreferredUsername().isPresent(),
                    "Preferred username should not be present");
        }
    }
}
