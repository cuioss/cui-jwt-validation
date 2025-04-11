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
package de.cuioss.jwt.token.domain.claim;

import de.cuioss.jwt.token.domain.claim.mapper.IdentityMapper;
import de.cuioss.jwt.token.domain.claim.mapper.JsonCollectionMapper;
import de.cuioss.jwt.token.domain.claim.mapper.OffsetDateTimeMapper;
import de.cuioss.jwt.token.domain.claim.mapper.ScopeMapper;
import jakarta.json.JsonObject;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

/**
 * Defines standard JWT claim names and their expected value types.
 * Based on RFC 7519, OpenID Connect, and OAuth 2.0 specifications.
 * Includes information about whether each claim is mandatory according to its
 * respective specification.
 * <p>
 * This is a replacement for the org.eclipse.microprofile.jwt.ClaimNames interface
 * to allow for migration from SmallRye JWT to JJWT without changing the existing code.
 */
@Getter
@RequiredArgsConstructor
public enum ClaimName {
    /**
     * The "iss" (issuer) claim identifies the principal that issued the JWT.
     * Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">RFC 7519 - 4.1.1. "iss" (Issuer) Claim</a>
     */
    ISSUER("iss", ClaimValueType.STRING) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new IdentityMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
     * Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 - 4.1.2. "sub" (Subject) Claim</a>
     */
    SUBJECT("sub", ClaimValueType.STRING) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new IdentityMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
     * Required by RFC 7519 for ID_TOKEN type.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">RFC 7519 - 4.1.3. "aud" (Audience) Claim</a>
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - ID Token</a>
     */
    AUDIENCE("aud", ClaimValueType.STRING_LIST) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new JsonCollectionMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "exp" (expiration time) claim identifies the expiration time on or after which
     * the JWT MUST NOT be accepted for processing.
     * Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 - 4.1.4. "exp" (Expiration Time) Claim</a>
     */
    EXPIRATION("exp", ClaimValueType.DATETIME) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new OffsetDateTimeMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT
     * MUST NOT be accepted for processing.
     * Optional by RFC 7519 for all token types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5">RFC 7519 - 4.1.5. "nbf" (Not Before) Claim</a>
     */
    NOT_BEFORE("nbf", ClaimValueType.DATETIME) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new OffsetDateTimeMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "iat" (issued at) claim identifies the time at which the JWT was issued.
     * Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6">RFC 7519 - 4.1.6. "iat" (Issued At) Claim</a>
     */
    ISSUED_AT("iat", ClaimValueType.DATETIME) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new OffsetDateTimeMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * Optional by RFC 7519 for all token types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">RFC 7519 - 4.1.7. "jti" (JWT ID) Claim</a>
     */
    TOKEN_ID("jti", ClaimValueType.STRING) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new IdentityMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "name" claim contains the full name of the end-user.
     * Optional for all token types.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 - Standard Claims</a>
     */
    NAME("name", ClaimValueType.STRING) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new IdentityMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "email" claim contains the preferred email address of the end-user.
     * Optional for all token types.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 - Standard Claims</a>
     */
    EMAIL("email", ClaimValueType.STRING) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new IdentityMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "preferred_username" claim contains the shorthand name by which the end-user
     * wishes to be referred to.
     * Optional for all token types.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 - Standard Claims</a>
     */
    PREFERRED_USERNAME("preferred_username", ClaimValueType.STRING) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new IdentityMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "scope" claim identifies the scope of the access token.
     * Required by RFC 6749 for ACCESS_TOKEN type.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">RFC 6749 - 3.3. Access Token Scope</a>
     */
    SCOPE("scope", ClaimValueType.STRING_LIST) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new ScopeMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "typ" claim identifies the token type.
     * Implementation-specific claim, not defined in standard specifications.
     */
    TYPE("typ", ClaimValueType.STRING) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new IdentityMapper().map(jsonObject, getName());
        }
    },

    /**
     * The "azp" (authorized party) claim identifies the party to which the ID Token was issued.
     * Optional by OpenID Connect Core 1.0 for ID_TOKEN type.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - ID Token</a>
     */
    AUTHORIZED_PARTY("azp", ClaimValueType.STRING) {
        @Override
        public @NonNull ClaimValue map(@NonNull JsonObject jsonObject) {
            return new IdentityMapper().map(jsonObject, getName());
        }
    };

    private final String name;
    private final ClaimValueType valueType;

    /**
     * Extract the claim value from the given JSON object using the appropriate mapper.
     *
     * @return the mapped ClaimValue
     */
    public abstract @NonNull ClaimValue map(@NonNull JsonObject jsonObject);

    /**
     * Gets a ClaimName by its string name.
     *
     * @param name the claim name string
     * @return an Optional containing the ClaimName if found, empty otherwise
     */
    public static Optional<ClaimName> fromString(String name) {
        if (name == null) {
            return Optional.empty();
        }

        for (ClaimName claimName : values()) {
            if (claimName.getName().equals(name)) {
                return Optional.of(claimName);
            }
        }

        return Optional.empty();
    }

}
