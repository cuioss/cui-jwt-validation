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
package de.cuioss.jwt.validation.domain.token;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.io.Serial;
import java.util.Map;

/**
 * Represents the content of an OAuth 2.0 refresh validation in JWT format.
 * This is only used when the refresh validation is in JWT format.
 */
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor
public class RefreshTokenContent implements MinimalTokenContent {

    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    @NonNull
    private final String rawToken;

    /**
     * For cases the idp returns a JWT as refresh validation, this method returns a non-validated-claims-representation
     * of the validation.
     * <em>Note:</em> This is validation is not validated in any way
     * It is never null but be empty
     */
    @Getter
    @NonNull
    private final Map<String, ClaimValue> claims;

    /**
     * Gets the validation type.
     *
     * @return always TokenType.REFRESH_TOKEN
     */
    @Override
    public TokenType getTokenType() {
        return TokenType.REFRESH_TOKEN;
    }

}