/*
 * Copyright 2025 the original author or authors.
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

import java.io.Serializable;

/**
 * Provides elements that are applicable on every Token.
 * Compare to the {@link TokenContent} this interface does not provide JWT-specific content like claims.
 * Currently, it is only relevant for {@link TokenType#REFRESH_TOKEN}
 */
public interface MinimalTokenContent extends Serializable {

    /**
     * Gets the raw validation string.
     *
     * @return the raw JWT validation string
     */
    String getRawToken();

    /**
     * Gets the validation type.
     *
     * @return the validation type (ACCESS_TOKEN, ID_TOKEN, or REFRESH_TOKEN)
     */
    TokenType getTokenType();
}
