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

import de.cuioss.jwt.token.domain.claim.ClaimName;
import de.cuioss.tools.logging.CuiLogger;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Collections;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import static de.cuioss.jwt.token.domain.claim.ClaimName.*;

/**
 * Defines the supported token types within the authentication system.
 * Each type represents a specific OAuth2/OpenID Connect token category with its corresponding type claim name.
 * <p>
 * The supported token types are:
 * <ul>
 *   <li>{@link #ACCESS_TOKEN}: Standard OAuth2 access token with "Bearer" type claim</li>
 *   <li>{@link #ID_TOKEN}: OpenID Connect ID token with "ID" type claim</li>
 *   <li>{@link #REFRESH_TOKEN}: OAuth2 refresh token with "Refresh" type claim</li>
 *   <li>{@link #UNKNOWN}: Fallback type for unrecognized or missing type claims</li>
 * </ul>
 * <p>
 * Note: The type claim implementation is specific to Keycloak and uses the "typ" claim
 * which is not part of the standard OAuth2/OpenID Connect specifications.
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public enum TokenType {

    ACCESS_TOKEN("Bearer", new TreeSet<>(List.of(ISSUER, EXPIRATION, ISSUED_AT, SUBJECT, SCOPE))),
    ID_TOKEN("ID", new TreeSet<>(List.of(ISSUER, EXPIRATION, ISSUED_AT, SUBJECT, AUDIENCE))),
    REFRESH_TOKEN("Refresh", Collections.emptySortedSet()),
    UNKNOWN("unknown", Collections.emptySortedSet());

    private static final CuiLogger LOGGER = new CuiLogger(TokenType.class);

    @Getter
    private final String typeClaimName;
    @Getter
    private final SortedSet<ClaimName> mandatoryClaims;

    public static TokenType fromTypClaim(String typeClaimName) {
        if (typeClaimName == null) {
            return UNKNOWN;
        }
        for (TokenType tokenType : TokenType.values()) {
            if (tokenType.typeClaimName.equalsIgnoreCase(typeClaimName)) {
                return tokenType;
            }
        }
        LOGGER.warn(JWTTokenLogMessages.WARN.UNKNOWN_TOKEN_TYPE.format(typeClaimName));
        return UNKNOWN;
    }
}
