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

import de.cuioss.jwt.token.adapter.JsonWebToken;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.Optional;

/**
 * Represents a parsed OAuth2 refresh token.
 * Can handle both opaque refresh tokens and JWT-formatted refresh tokens.
 */
@ToString
public class ParsedRefreshToken implements Serializable {

    private static final CuiLogger LOGGER = new CuiLogger(ParsedRefreshToken.class);

    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    private final String tokenString;

    private final JsonWebToken jwtContent; // Optional for JWT refresh tokens
    
    /**
     * Creates a new ParsedRefreshToken with the given token string.
     * Use this constructor for opaque refresh tokens.
     *
     * @param tokenString the refresh token string
     */
    public ParsedRefreshToken(String tokenString) {
        this(tokenString, null);
    }

    /**
     * Creates a new ParsedRefreshToken with the given token string and JWT content.
     * Use this constructor for JWT-formatted refresh tokens.
     *
     * @param tokenString the refresh token string
     * @param jwtContent the JWT content (may be null for opaque tokens)
     */
    public ParsedRefreshToken(String tokenString, JsonWebToken jwtContent) {
        this.tokenString = tokenString;
        this.jwtContent = jwtContent;
    }

    /**
     * Checks if the token is empty.
     *
     * @return true if the token is empty, false otherwise
     */
    public boolean isEmpty() {
        return MoreStrings.isEmpty(tokenString);
    }

    /**
     * Checks if the token is in JWT format.
     *
     * @return true if the token is in JWT format, false otherwise
     */
    public boolean isJwtFormat() {
        return jwtContent != null;
    }

    /**
     * Gets the raw token string.
     *
     * @return the raw token string
     */
    public String getRawToken() {
        return tokenString;
    }

    /**
     * Gets the token content if it's in JWT format.
     *
     * @return an Optional containing the token content if in JWT format, or empty otherwise
     */
    public Optional<JsonWebToken> getJwtContent() {
        return Optional.ofNullable(jwtContent);
    }

    /**
     * Gets the JSON Web Token if it's in JWT format.
     * Alias for getJwtContent() for compatibility with tests.
     *
     * @return an Optional containing the JSON Web Token if in JWT format, or empty otherwise
     */
    public Optional<JsonWebToken> getJsonWebToken() {
        return getJwtContent();
    }

    /**
     * Gets the token type.
     *
     * @return the token type
     */
    public TokenType getType() {
        return TokenType.REFRESH_TOKEN;
    }
}