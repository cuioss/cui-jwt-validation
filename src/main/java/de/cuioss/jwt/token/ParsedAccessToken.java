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

import de.cuioss.jwt.token.adapter.Claims;
import de.cuioss.jwt.token.adapter.JsonWebToken;
import de.cuioss.tools.collect.MoreCollections;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.Splitter;
import jakarta.json.JsonArray;
import jakarta.json.JsonString;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.Delegate;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import static java.util.stream.Collectors.toSet;

/**
 * Represents a parsed OAuth2 access token with enhanced functionality for scope and role management.
 * Provides convenient access to standard OAuth2 claims as well as additional OpenID Connect claims.
 * <p>
 * This class directly implements the {@link JsonWebToken} interface using delegation to a
 * {@link JsonWebToken} instance, allowing for flexible composition and better separation of concerns.
 * <p>
 * Key features:
 * <ul>
 *   <li>Scope management and validation</li>
 *   <li>Role-based access control</li>
 *   <li>User identity information (subject ID, email, name)</li>
 * </ul>
 * <p>
 * The token supports the following claims:
 * <ul>
 *   <li>{@link #CLAIM_NAME_SCOPE}: Space-separated list of OAuth2 scopes</li>
 *   <li>{@link #CLAIM_NAME_ROLES}: JSON array of assigned roles</li>
 *   <li>{@link Claims#EMAIL}: User's email address</li>
 *   <li>{@link Claims#PREFERRED_USERNAME}: User's preferred username</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * TokenFactory factory = TokenFactory.builder()
 *     .addParser(parser)
 *     .build();
 * Optional&lt;ParsedAccessToken&gt; token = factory.createAccessToken(tokenString);
 * if (token.isPresent() &amp;&amp; token.get().providesScopes(requiredScopes)) {
 *     // Token is valid and has required scopes
 * }
 * </pre>
 * <p>
 * See specification: {@code doc/specification/technical-components.adoc#_token_classes}
 * <p>
 * Implements requirement: {@code CUI-JWT-2.2: Access Token Functionality}
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class ParsedAccessToken implements JsonWebToken {

    private static final CuiLogger LOGGER = new CuiLogger(ParsedAccessToken.class);

    /**
     * The name for the scopes-claim.
     */
    public static final String CLAIM_NAME_SCOPE = "scope";
    private static final String CLAIM_NAME_ROLES = "roles";

    @Getter
    @Delegate
    private final JsonWebToken jsonWebToken;

    private final String email;

    /**
     * Creates a new {@link ParsedAccessToken} from64EncodedContent the given JsonWebToken and email.
     *
     * @param jsonWebToken The JsonWebToken to wrap, must not be null
     * @param email        The email address associated with this token, may be null
     */
    public ParsedAccessToken(JsonWebToken jsonWebToken, String email) {
        this.jsonWebToken = jsonWebToken;
        this.email = email;
    }

    /**
     * @return a {@link Set} representing all scopes. If none can be found, it returns an empty set
     */
    public Set<String> getScopes() {
        if (!jsonWebToken.containsClaim(CLAIM_NAME_SCOPE)) {
            LOGGER.debug("No scope claim found in token");
            return Set.of();
        }

        var result = Splitter.on(' ').splitToList(jsonWebToken.getClaim(CLAIM_NAME_SCOPE));
        LOGGER.debug("Found scopes in token: %s", result);
        return new TreeSet<>(result);
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
     * @return the roles defined in the 'roles' claim of the token
     */
    public Set<String> getRoles() {
        LOGGER.debug("Retrieving roles from64EncodedContent token");
        if (!jsonWebToken.containsClaim(CLAIM_NAME_ROLES)) {
            LOGGER.debug("No roles claim found in token, containsClaim returned false");
            return Set.of();
        }

        var roles = jsonWebToken.getClaim(CLAIM_NAME_ROLES);
        LOGGER.debug("Roles claim value: %s (type: %s)", roles, roles != null ? roles.getClass().getName() : "null");

        if (roles instanceof JsonArray array) {
            var result = array.getValuesAs(JsonString.class).stream()
                    .map(JsonString::getString)
                    .collect(toSet());
            LOGGER.debug("Found roles in token as JsonArray: %s", result);
            return result;
        } else if (roles instanceof Set<?> set) {
            // Handle the case where roles is a Set<String> (as in AccessTokenGenerator)
            var result = set.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .collect(toSet());
            LOGGER.debug("Found roles in token as Set: %s", result);
            return result;
        } else if (roles instanceof java.util.Collection<?> collection) {
            // Handle the case where roles is any other Collection type
            var result = collection.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .collect(toSet());
            LOGGER.debug("Found roles in token as Collection: %s", result);
            return result;
        }
        LOGGER.debug("Roles claim is not a JsonArray, Set, or Collection");
        return Set.of();
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
     * Resolves the email address. Either given or extracted from64EncodedContent the token.
     *
     * @return an optional containing the potential email
     */
    public Optional<String> getEmail() {
        return Optional
                .ofNullable(email)
                .or(() -> Optional.ofNullable(jsonWebToken.getClaim(Claims.EMAIL)));
    }

    /**
     * Resolves the preferred username from64EncodedContent the token.
     *
     * @return an optional containing the potential preferred username
     */
    public Optional<String> getPreferredUsername() {
        return Optional.ofNullable(jsonWebToken.getClaim(Claims.PREFERRED_USERNAME));
    }

}
