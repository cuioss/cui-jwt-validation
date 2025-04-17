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

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.claim.ClaimName;
import de.cuioss.jwt.token.domain.claim.ClaimValue;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.io.Serial;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Represents the content of an OpenID Connect ID token.
 * Provides access to ID token specific claims.
 */
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@SuperBuilder
public class IdTokenContent extends BaseTokenContent {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new IdTokenContent with the given claims and raw token.
     *
     * @param claims   the token claims
     * @param rawToken the raw token string
     */
    public IdTokenContent(Map<String, ClaimValue> claims, String rawToken) {
        super(claims, rawToken, TokenType.ID_TOKEN);
    }

    /**
     * Gets the audience claim value.
     * <p>
     * 'aud' is mandatory for {@link TokenType#ID_TOKEN}.
     *
     * @return the audience as a list of strings, or throws exception if it's not present
     * @throws IllegalStateException if the audience claim is not present
     */
    public List<String> getAudience() {
        return getClaimOption(ClaimName.AUDIENCE)
                .map(ClaimValue::getAsList)
                .orElseThrow(() -> new IllegalStateException("Audience claim not present in token"));
    }

    /**
     * Gets the name from the token claims.
     *
     * @return an Optional containing the name if present, or empty otherwise
     */
    public Optional<String> getName() {
        return getClaimOption(ClaimName.NAME)
                .map(ClaimValue::getOriginalString);
    }

    /**
     * Gets the email from the token claims.
     *
     * @return an Optional containing the email if present, or empty otherwise
     */
    public Optional<String> getEmail() {
        return getClaimOption(ClaimName.EMAIL)
                .map(ClaimValue::getOriginalString);
    }

}
