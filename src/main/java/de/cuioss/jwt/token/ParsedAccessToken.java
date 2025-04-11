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

import de.cuioss.jwt.token.adapter.ClaimNames;
import de.cuioss.jwt.token.adapter.JsonWebToken;
import de.cuioss.tools.collect.MoreCollections;
import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.*;

/**
 * Represents a parsed OAuth2 access token.
 * Acts as a Data Transfer Object without dynamic computation logic.
 * <p>
 * Key features:
 * <ul>
 *   <li>Scope management and validation</li>
 *   <li>Role-based access control</li>
 *   <li>User identity information (subject ID, email, name)</li>
 * </ul>
 */
@ToString
@EqualsAndHashCode
public class ParsedAccessToken implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;
    private static final CuiLogger LOGGER = new CuiLogger(ParsedAccessToken.class);

    @Getter
    private final JsonWebToken jwt;

    private final String email;

    /**
     * Creates a new ParsedAccessToken with the given JsonWebToken.
     *
     * @param jwt   the JsonWebToken
     * @param email the email associated with the token (may be null)
     */
    public ParsedAccessToken(JsonWebToken jwt, String email) {
        this.jwt = jwt;
        this.email = email;
    }

    /**
     * Gets the scopes in this token.
     *
     * @return the set of scopes
     */
    @SuppressWarnings("unchecked")
    public SortedSet<String> getScopes() {
        SortedSet<String> scopes = new TreeSet<>();
        Object scopeObj = jwt.getClaim(ClaimNames.SCOPE);

        if (scopeObj instanceof String scopeStr) {
            if (!scopeStr.isBlank()) {
                for (String scope : scopeStr.split("\\s+")) {
                    scopes.add(scope.trim());
                }
            }
        } else if (scopeObj instanceof Collection) {
            // Handle array of scopes
            try {
                Collection<String> scopeColl = (Collection<String>) scopeObj;
                scopes.addAll(scopeColl);
            } catch (ClassCastException e) {
                LOGGER.warn("Invalid scope claim format: {}", e.getMessage());
            }
        }

        return scopes;
    }

    /**
     * Gets the roles in this token.
     *
     * @return the set of roles
     */
    @SuppressWarnings("unchecked")
    public SortedSet<String> getRoles() {
        SortedSet<String> roles = new TreeSet<>();

        // Try to get roles from various possible claims
        for (String rolesClaim : new String[]{"roles", "realm_access/roles", "resource_access/*/roles"}) {
            Object rolesObj = jwt.getClaim(rolesClaim);
            if (rolesObj instanceof Collection) {
                try {
                    Collection<String> rolesColl = (Collection<String>) rolesObj;
                    roles.addAll(rolesColl);
                } catch (ClassCastException e) {
                    LOGGER.warn("Invalid roles claim format: {}", e.getMessage());
                }
            }
        }

        return roles;
    }

    /**
     * Gets the raw token string.
     *
     * @return the raw token string
     */
    public String getRawToken() {
        return jwt.getRawToken();
    }

    /**
     * Gets the token issuer.
     *
     * @return the issuer
     */
    public String getIssuer() {
        return jwt.getIssuer();
    }

    /**
     * Gets the token subject.
     *
     * @return the subject
     */
    public String getSubject() {
        return jwt.getSubject();
    }

    /**
     * Gets the token type.
     *
     * @return the token type
     */
    public TokenType getType() {
        return TokenType.ACCESS_TOKEN;
    }

    /**
     * Gets the name associated with this token.
     *
     * @return an Optional containing the name if present, or empty otherwise
     */
    public Optional<String> getName() {
        return jwt.getName();
    }

    /**
     * Gets the underlying JsonWebToken implementation.
     *
     * @return the JsonWebToken
     */
    public JsonWebToken getJsonWebToken() {
        return jwt;
    }

    /**
     * Checks if the token has expired.
     *
     * @return true if the token has expired, false otherwise
     */
    public boolean isExpired() {
        return jwt.isExpired();
    }

    /**
     * @param expectedScopes to be checked
     * @return boolean indicating whether the token provides all given Scopes
     */
    public boolean providesScopes(Collection<String> expectedScopes) {
        if (null == expectedScopes || expectedScopes.isEmpty()) {
            LOGGER.debug("No scopes to check against");
            return true;
        }
        var availableScopes = getScopes();
        var result = availableScopes.containsAll(expectedScopes);
        LOGGER.debug("Scope check result=%s (expected=%s, available=%s)", result, expectedScopes, availableScopes);
        return result;
    }

    /**
     * @param expectedScopes to be checked
     * @param logContext     Usually
     * @return boolean indicating whether the token provides all given Scopes. In contrast to
     * {@link #providesScopes(Collection)} it log on debug the corresponding scopes
     */
    public boolean providesScopesAndDebugIfScopesAreMissing(Collection<String> expectedScopes, String logContext,
            CuiLogger logger) {
        Set<String> delta = determineMissingScopes(expectedScopes);
        if (delta.isEmpty()) {
            logger.trace("All expected scopes are present: {}, {}", expectedScopes, logContext);
            return true;
        }
        logger.debug(
                "Current Token does not provide all needed scopes:\nMissing in token='{}',\nExpected='{}'\nPresent in Token='{}', {}",
                delta, expectedScopes, getScopes(), logContext);
        return false;
    }

    /**
     * @param expectedScopes to be checked
     * @return an empty-Set in case the token provides all expectedScopes, otherwise a
     * {@link TreeSet} containing all missing scopes.
     */
    public Set<String> determineMissingScopes(Collection<String> expectedScopes) {
        if (providesScopes(expectedScopes)) {
            return Collections.emptySet();
        }
        Set<String> scopeDelta = new TreeSet<>(expectedScopes);
        scopeDelta.removeAll(getScopes());
        return scopeDelta;
    }

    /**
     * Checks if the expected role is present within the 'roles' claim of the token.
     *
     * @param expectedRole the expected role
     * @return if the role is present
     */
    public boolean hasRole(String expectedRole) {
        return getRoles().contains(expectedRole);
    }

    /**
     * @param expectedRoles to be checked
     * @return an empty-Set in case the token provides all expectedRoles, otherwise a
     * {@link TreeSet} containing all missing roles.
     */
    public Set<String> determineMissingRoles(Collection<String> expectedRoles) {
        if (MoreCollections.isEmpty(expectedRoles)) {
            return Collections.emptySet();
        }
        Set<String> availableRoles = getRoles();
        if (availableRoles.containsAll(expectedRoles)) {
            return Collections.emptySet();
        }
        Set<String> roleDelta = new TreeSet<>(expectedRoles);
        roleDelta.removeAll(availableRoles);
        return roleDelta;
    }

    /**
     * Gets the email address associated with this token.
     *
     * @return an Optional containing the email if present, or empty otherwise
     */
    public Optional<String> getEmail() {
        if (email != null) {
            return Optional.of(email);
        }
        return jwt.claim("email");
    }

    /**
     * Gets the preferred username from the token.
     *
     * @return an Optional containing the preferred username if present, or empty otherwise
     */
    public Optional<String> getPreferredUsername() {
        return jwt.claim("preferred_username");
    }
}