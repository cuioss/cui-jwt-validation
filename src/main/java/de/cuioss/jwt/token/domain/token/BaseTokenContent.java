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
import de.cuioss.jwt.token.domain.claim.ClaimValue;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.io.Serial;
import java.util.Map;

/**
 * Base implementation of {@link TokenContent}.
 * Provides common functionality for token content implementations.
 */
@ToString
@EqualsAndHashCode
@SuperBuilder
public abstract class BaseTokenContent implements TokenContent {

    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    @NonNull
    private final Map<String, ClaimValue> claims;

    @Getter
    @NonNull
    private final String rawToken;

    @Getter
    @NonNull
    private final TokenType tokenType;

    /**
     * Constructor for BaseTokenContent.
     *
     * @param claims    the token claims
     * @param rawToken  the raw token string
     * @param tokenType the token type
     */
    protected BaseTokenContent(@NonNull Map<String, ClaimValue> claims, @NonNull String rawToken, @NonNull TokenType tokenType) {
        this.claims = claims;
        this.rawToken = rawToken;
        this.tokenType = tokenType;
    }
}
