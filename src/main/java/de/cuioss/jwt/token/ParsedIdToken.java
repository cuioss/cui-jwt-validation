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
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.Optional;

/**
 * Represents a parsed OpenID Connect ID token.
 * Acts as a Data Transfer Object without dynamic computation logic.
 */
@ToString
@EqualsAndHashCode
public class ParsedIdToken implements Serializable {

    @Serial
    private static final long serialVersionUID = -3863682323652008837L;

    private static final CuiLogger LOGGER = new CuiLogger(ParsedIdToken.class);

    @Getter
    private final JsonWebToken jwt;

    /**
     * Creates a new ParsedIdToken with the given JsonWebToken.
     *
     * @param jwt the JsonWebToken
     */
    public ParsedIdToken(JsonWebToken jwt) {
        this.jwt = jwt;
    }

    /**
     * Gets the raw token string.
     *
     * @return the raw token string
     */
    public String getRawToken() {
        return jwt.getRawToken();
    }

    /**
     * Gets the token issuer.
     *
     * @return the issuer
     */
    public String getIssuer() {
        return jwt.getIssuer();
    }

    /**
     * Gets the token subject.
     *
     * @return the subject
     */
    public String getSubject() {
        return jwt.getSubject();
    }

    /**
     * Gets the name from the token.
     *
     * @return an Optional containing the name if present, or empty otherwise
     */
    public Optional<String> getName() {
        return jwt.getName();
    }

    /**
     * Gets the underlying JsonWebToken implementation.
     * 
     * @return the JsonWebToken
     */
    public JsonWebToken getJsonWebToken() {
        return jwt;
    }

    /**
     * Gets the email from the token.
     *
     * @return an Optional containing the email if present, or empty otherwise
     */
    public Optional<String> getEmail() {
        return jwt.claim("email");
    }

    /**
     * Gets the token type.
     *
     * @return the token type
     */
    public TokenType getType() {
        return TokenType.ID_TOKEN;
    }

    /**
     * Checks if the token has expired.
     *
     * @return true if the token has expired, false otherwise
     */
    public boolean isExpired() {
        return jwt.isExpired();
    }
}