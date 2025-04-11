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

import de.cuioss.jwt.token.domain.claim.ClaimName;
import de.cuioss.jwt.token.domain.claim.ClaimValue;
import de.cuioss.tools.logging.CuiLogger;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;

/**
 * Base interface for JWT token content.
 * Provides access to claims. Raw token string and token type are provided through {@link MinimalTokenContent}.
 */
public interface TokenContent extends MinimalTokenContent {

    CuiLogger LOGGER = new CuiLogger(TokenContent.class);

    /**
     * Gets all claims in this token.
     *
     * @return a map of claim names to claim objects
     */
    Map<String, ClaimValue> getClaims();

    /**
     * Gets a specific claim by name.
     *
     * @param name the claim name
     * @return an Optional containing the claim if present, or empty otherwise
     */
    default Optional<ClaimValue> getClaimOption(ClaimName name) {
        return Optional.ofNullable(getClaims().get(name.getName()));
    }

    /**
     * Gets the issuer claim value.
     * <p>
     * Since 'iss' is a mandatory claim, this method will never return null.
     *
     * @return the issuer
     * @throws IllegalStateException if the issuer claim is not present (should never happen
     *                               for a properly constructed token)
     */
    default String getIssuer() {
        return getClaimOption(ClaimName.ISSUER)
                .map(ClaimValue::getOriginalString)
                .orElseThrow(() -> new IllegalStateException("Issuer claim not present in token"));
    }

    /**
     * Gets the subject claim value.
     * <p>
     * Since 'sub' is a mandatory claim for most token types, this method will never return null.
     *
     * @return the subject, or throws exception if it's not present
     * @throws IllegalStateException if the subject claim is not present
     */
    default String getSubject() {
        return getClaimOption(ClaimName.SUBJECT)
                .map(ClaimValue::getOriginalString)
                .orElseThrow(() -> new IllegalStateException("Subject claim not present in token"));
    }

    /**
     * Gets the expiration time claim value.
     * <p>
     * Since 'exp' is a mandatory claim, this method will never return null.
     *
     * @return the expiration time
     * @throws IllegalStateException if the expiration claim is not present (should never happen
     *                               for a properly constructed token)
     */
    default OffsetDateTime getExpirationTime() {
        return getClaimOption(ClaimName.EXPIRATION)
                .map(ClaimValue::getDateTime)
                .orElseThrow(() -> new IllegalStateException("ExpirationTime claim not present in token"));
    }

    /**
     * Gets the issued at time claim value.
     * <p>
     * Since 'iat' is a mandatory claim, this method will never return null.
     *
     * @return the issued at time
     * @throws IllegalStateException if the issued at claim is not present (should never happen
     *                               for a properly constructed token)
     */
    default OffsetDateTime getIssuedAtTime() {
        return getClaimOption(ClaimName.ISSUED_AT)
                .map(ClaimValue::getDateTime)
                .orElseThrow(() -> new IllegalStateException("issued at time claim claim not present in token"));
    }

    /**
     * Gets the optional not before claim value.
     * <p>
     * Since 'nbf' is optional, this method may return an empty Optional.
     *
     * @return the 'not before time''
     */
    default Optional<OffsetDateTime> getNotBefore() {
        return getClaimOption(ClaimName.NOT_BEFORE)
                .map(ClaimValue::getDateTime);
    }

    /**
     * Checks if the token has expired.
     *
     * @return true if the token has expired, false otherwise
     */
    default boolean isExpired() {
        return getExpirationTime().isBefore(OffsetDateTime.now());
    }
}