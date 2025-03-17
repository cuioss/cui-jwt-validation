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
package de.cuioss.jwt.token.adapter;

import java.util.Optional;
import java.util.Set;

/**
 * Interface that represents a JSON Web Token (JWT).
 * This is a replacement for the org.eclipse.microprofile.jwt.JsonWebToken interface
 * to allow for migration from SmallRye JWT to JJWT without changing the existing code.
 * <p>
 * The interface provides methods for accessing the standard JWT claims as defined in RFC 7519,
 * as well as additional methods for working with custom claims.
 *
 * @author Oliver Wolff
 */
public interface JsonWebToken {

    /**
     * Returns the name of the JWT, which is the 'name' claim.
     *
     * @return the name of the JWT
     */
    String getName();

    /**
     * Returns the set of claim names present in the JWT.
     *
     * @return the set of claim names
     */
    Set<String> getClaimNames();

    /**
     * Returns the value of the specified claim.
     *
     * @param claimName the name of the claim
     * @param <T> the type of the claim value
     * @return the value of the claim, or null if the claim is not present
     */
    <T> T getClaim(String claimName);

    /**
     * Checks if the token contains the specified claim.
     *
     * @param claimName the name of the claim
     * @return true if the token contains the claim, false otherwise
     */
    default boolean containsClaim(String claimName) {
        return getClaimNames().contains(claimName);
    }

    /**
     * Returns the raw token string.
     *
     * @return the raw token string
     */
    String getRawToken();

    /**
     * Returns the issuer of the JWT, which is the 'iss' claim.
     *
     * @return the issuer of the JWT
     */
    String getIssuer();

    /**
     * Returns the subject of the JWT, which is the 'sub' claim.
     *
     * @return the subject of the JWT
     */
    String getSubject();

    /**
     * Returns the audience of the JWT, which is the 'aud' claim.
     *
     * @return the audience of the JWT
     */
    Set<String> getAudience();

    /**
     * Returns the expiration time of the JWT, which is the 'exp' claim.
     *
     * @return the expiration time of the JWT in seconds since the epoch
     */
    long getExpirationTime();

    /**
     * Returns the issued at time of the JWT, which is the 'iat' claim.
     *
     * @return the issued at time of the JWT in seconds since the epoch
     */
    long getIssuedAtTime();

    /**
     * Returns the token ID of the JWT, which is the 'jti' claim.
     *
     * @return the token ID of the JWT
     */
    String getTokenID();

    /**
     * Returns the groups of the JWT, which is the 'groups' claim.
     *
     * @return the groups of the JWT
     */
    Set<String> getGroups();

    /**
     * Returns the value of the specified claim as an Optional.
     *
     * @param name the name of the claim
     * @param <T> the type of the claim value
     * @return an Optional containing the claim value, or empty if the claim is not present
     */
    default <T> Optional<T> claim(String name) {
        T value = getClaim(name);
        return Optional.ofNullable(value);
    }
}
