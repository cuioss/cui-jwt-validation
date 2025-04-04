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
 * Represents a parsed OAuth2 refresh token with basic validation support.
 * Unlike access and ID tokens, refresh tokens are treated as opaque strings
 * as per OAuth2 specification, though some implementations (like Keycloak) may use JWTs.
 * <p>
 * Key features:
 * <ul>
 *   <li>Simple token string validation</li>
 *   <li>Type-safe token representation</li>
 *   <li>Immutable and thread-safe implementation</li>
 *   <li>Optional support for JWT-formatted refresh tokens</li>
 * </ul>
 * <p>
 * Note: While OAuth2 specification treats refresh tokens as opaque strings,
 * this implementation supports Keycloak's JWT-based refresh tokens.
 * The validation is minimal and does not include JWT signature verification.
 * <p>
 * Usage example:
 * <pre>
 * TokenFactory factory = TokenFactory.builder()
 *     .addParser(parser)
 *     .build();
 * Optional&lt;ParsedRefreshToken&gt; optionalToken = factory.createRefreshToken(tokenString);
 * if (optionalToken.isPresent() &amp;&amp; !optionalToken.get().isEmpty()) {
 *     // Use the token
 *     optionalToken.get().getJsonWebToken().ifPresent(jwt -> {
 *         // Access JWT claims if the refresh token is a JWT
 *     });
 * }
 * </pre>
 *
 * @author Oliver Wolff
 */
@ToString
public class ParsedRefreshToken implements Serializable {

    private static final CuiLogger LOGGER = new CuiLogger(ParsedRefreshToken.class);

    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    private final String tokenString;
    
    private final JsonWebToken jsonWebToken;

    /**
     * Creates a new {@link ParsedRefreshToken} from the given token string.
     * <p>
     * Note: This constructor does not validate the token's signature or format.
     * It only wraps the string for type-safety purposes.
     *
     * @param tokenString The raw refresh token string, may be null or empty
     */
    public ParsedRefreshToken(String tokenString) {
        this(tokenString, null);
    }
    
    /**
     * Creates a new {@link ParsedRefreshToken} from the given token string and optional JsonWebToken.
     * <p>
     * This constructor supports handling refresh tokens in JWT format by storing the parsed JWT
     * for easy access to its claims.
     *
     * @param tokenString The raw refresh token string, may be null or empty
     * @param jsonWebToken The parsed JWT if the token is in JWT format, may be null
     */
    public ParsedRefreshToken(String tokenString, JsonWebToken jsonWebToken) {
        if (MoreStrings.isEmpty(tokenString)) {
            LOGGER.debug("Creating refresh token from empty token string");
        }
        this.tokenString = tokenString;
        this.jsonWebToken = jsonWebToken;
    }

    /**
     * Indicates whether the token is empty (null or blank string).
     *
     * @return {@code true} if the token is null or empty, {@code false} otherwise
     */
    public boolean isEmpty() {
        return MoreStrings.isEmpty(tokenString);
    }

    /**
     * Returns the type of this token.
     *
     * @return always {@link TokenType#REFRESH_TOKEN}
     */
    public TokenType getType() {
        return TokenType.REFRESH_TOKEN;
    }

    /**
     * Returns the token as encoded String.
     * This method is provided for consistency with the JsonWebToken interface.
     *
     * @return the token as encoded String.
     */
    public String getRawToken() {
        return tokenString;
    }
    
    /**
     * Returns the JsonWebToken representation of this refresh token if it's in JWT format.
     * <p>
     * This method allows accessing JWT-specific properties if the refresh token is a JWT,
     * while still treating it as an opaque string for compatibility with OAuth2 specifications.
     *
     * @return an Optional containing the JsonWebToken if the refresh token is in JWT format, or empty otherwise
     */
    public Optional<JsonWebToken> getJsonWebToken() {
        return Optional.ofNullable(jsonWebToken);
    }
    
    /**
     * Indicates whether this refresh token is in JWT format.
     *
     * @return {@code true} if the token is in JWT format and can be parsed as a JWT, {@code false} otherwise
     */
    public boolean isJwtFormat() {
        return jsonWebToken != null;
    }
}
