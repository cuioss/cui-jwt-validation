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

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.Set;

/**
 * Interface that represents a JSON Web Token (JWT).
 * This is a replacement for the org.eclipse.microprofile.jwt.JsonWebToken interface
 * to allow for migration from SmallRye JWT to JJWT without changing the existing code.
 * <p>
 * The interface provides methods for accessing the standard JWT claims as defined in RFC 7519,
 * as well as additional methods for working with custom claims.
 * <p>
 * JWT claims can be categorized as follows:
 * <ul>
 *   <li><strong>Required by JWT spec (RFC 7519):</strong> None. All claims are optional per the spec.</li>
 *   <li><strong>Required by this implementation:</strong> iss, sub, exp, iat</li>
 *   <li><strong>Optional but validated if present:</strong> nbf</li>
 *   <li><strong>Optional:</strong> jti, aud, groups, name</li>
 * </ul>
 * <p>
 * Different token types have additional requirements:
 * <ul>
 *   <li><strong>Access Tokens (OAuth 2.0):</strong> Required: iss, sub, exp, iat. Optional: scope, roles, name, email, preferred_username</li>
 *   <li><strong>ID Tokens (OpenID Connect):</strong> Required: iss, sub, exp, iat, aud. Optional: email</li>
 *   <li><strong>Refresh Tokens:</strong> Treated as opaque strings in this implementation, no JWT validation</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0 Authorization Framework</a>
 */
public interface JsonWebToken {

    /**
     * Returns the name of the JWT, which is the 'name' claim.
     * <p>
     * This claim is optional for all token types.
     * <p>
     * For ID tokens, this represents the end-user's full name as specified in OpenID Connect Core 1.0.
     *
     * @return an Optional containing the name of the JWT, or empty if not present
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 - Standard Claims</a>
     */
    Optional<String> getName();

    /**
     * Returns the set of claim names present in the JWT.
     * <p>
     * This method provides access to all claims in the token, including both standard
     * claims defined in RFC 7519 and custom claims specific to the token issuer.
     *
     * @return the set of claim names
     */
    Set<String> getClaimNames();

    /**
     * Returns the value of the specified claim.
     * <p>
     * This method provides access to any claim in the token, including both standard
     * claims defined in RFC 7519 and custom claims specific to the token issuer.
     * <p>
     * The return type is determined by the claim's value type in the JWT:
     * <ul>
     *   <li>String values for string claims</li>
     *   <li>Number values for numeric claims</li>
     *   <li>Boolean values for boolean claims</li>
     *   <li>Map values for object claims</li>
     *   <li>List values for array claims</li>
     * </ul>
     *
     * @param claimName the name of the claim
     * @param <T>       the type of the claim value
     * @return the value of the claim, or null if the claim is not present
     */
    <T> T getClaim(String claimName);

    /**
     * Checks if the token contains the specified claim.
     * <p>
     * This method can be used to verify the presence of both standard claims
     * defined in RFC 7519 and custom claims specific to the token issuer.
     *
     * @param claimName the name of the claim
     * @return true if the token contains the claim, false otherwise
     */
    default boolean containsClaim(String claimName) {
        return getClaimNames().contains(claimName);
    }

    /**
     * Returns the raw token string.
     * <p>
     * This method provides access to the original, encoded JWT string in the format:
     * header.payload.signature
     *
     * @return the raw token string
     */
    String getRawToken();

    /**
     * Returns the issuer of the JWT, which is the 'iss' claim.
     * <p>
     * This claim is required for all token types in this implementation.
     * <p>
     * The "iss" (issuer) claim identifies the principal that issued the JWT.
     * The value is a case-sensitive string containing a StringOrURI value.
     *
     * @return the issuer of the JWT
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">RFC 7519 - 4.1.1. "iss" (Issuer) Claim</a>
     */
    String getIssuer();

    /**
     * Returns the subject of the JWT, which is the 'sub' claim.
     * <p>
     * This claim is required for all token types in this implementation.
     * <p>
     * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
     * The value is a case-sensitive string containing a StringOrURI value.
     *
     * @return the subject of the JWT
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 - 4.1.2. "sub" (Subject) Claim</a>
     */
    String getSubject();

    /**
     * Returns the audience of the JWT, which is the 'aud' claim.
     * <p>
     * This claim is optional for Access Tokens but required for ID Tokens according to OpenID Connect Core 1.0.
     * <p>
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
     * The value is an array of case-sensitive strings, each containing a StringOrURI value.
     *
     * @return an Optional containing the audience of the JWT, or empty if not present
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">RFC 7519 - 4.1.3. "aud" (Audience) Claim</a>
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - ID Token</a>
     */
    Optional<Set<String>> getAudience();

    /**
     * Returns the expiration time of the JWT, which is the 'exp' claim.
     * <p>
     * This claim is required for all token types in this implementation.
     * <p>
     * The "exp" (expiration time) claim identifies the expiration time on or after which
     * the JWT MUST NOT be accepted for processing. The value is a NumericDate value.
     *
     * @return the expiration time of the JWT as an OffsetDateTime
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 - 4.1.4. "exp" (Expiration Time) Claim</a>
     */
    OffsetDateTime getExpirationTime();

    /**
     * @return boolean indicating whether the token is already expired. Shorthand for
     * {@link #willExpireInSeconds(int)}
     * with '0'.
     */
    default boolean isExpired() {
        return willExpireInSeconds(0);
    }

    /**
     * @param seconds maybe {@code 0}. Calling it with a negative number is not defined.
     * @return boolean indicating whether the token will expired within the given number of seconds.
     */
    default boolean willExpireInSeconds(int seconds) {
        return getExpirationTime().isBefore(OffsetDateTime.now().plusSeconds(seconds));
    }

    /**
     * Returns the issued at time of the JWT, which is the 'iat' claim.
     * <p>
     * This claim is required for all token types in this implementation.
     * <p>
     * The "iat" (issued at) claim identifies the time at which the JWT was issued.
     * The value is a NumericDate value.
     *
     * @return the issued at time of the JWT as an OffsetDateTime
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6">RFC 7519 - 4.1.6. "iat" (Issued At) Claim</a>
     */
    OffsetDateTime getIssuedAtTime();

    /**
     * Returns the "Not Before" time from the token if present, which is the 'nbf' claim.
     * <p>
     * This claim is optional, according to the JWT specification (RFC 7519).
     * <p>
     * The "nbf" (not before) claim identifies the time before which the JWT must not be accepted for processing.
     * The value is a NumericDate value.
     *
     * @return an Optional containing the "Not Before" time as an OffsetDateTime, or empty if not present
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5">RFC 7519 - 4.1.5. "nbf" (Not Before) Claim</a>
     */
    Optional<OffsetDateTime> getNotBeforeTime();

    /**
     * Returns the token ID of the JWT, which is the 'jti' claim.
     * <p>
     * This claim is optional for all token types.
     * <p>
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * The value is a case-sensitive string.
     *
     * @return an Optional containing the token ID of the JWT, or empty if not present
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">RFC 7519 - 4.1.7. "jti" (JWT ID) Claim</a>
     */
    Optional<String> getTokenID();


    /**
     * Returns the value of the specified claim as an Optional.
     * <p>
     * This is a convenience method that wraps {@link #getClaim(String)} in an Optional
     * to provide a more modern API for handling potentially absent claims.
     * <p>
     * This method can be used to access any claim in the token, including both standard
     * claims defined in RFC 7519 and custom claims specific to the token issuer.
     *
     * @param name the name of the claim
     * @param <T>  the type of the claim value
     * @return an Optional containing the claim value, or empty if the claim is not present
     */
    default <T> Optional<T> claim(String name) {
        T value = getClaim(name);
        return Optional.ofNullable(value);
    }

    /**
     * Extracts the {@link de.cuioss.jwt.token.TokenType} from the claim "type."
     * <em>Caution:</em> This is only tested for keycloak.
     * The claim 'typ' is not from the oauth spec.
     * 
     * @return the token type based on the "typ" claim
     */
    default de.cuioss.jwt.token.TokenType getType() {
        return de.cuioss.jwt.token.TokenType.fromTypClaim(getClaim("typ"));
    }
}
