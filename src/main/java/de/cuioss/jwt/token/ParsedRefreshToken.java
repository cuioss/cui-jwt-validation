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

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

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
 * if (optionalToken.isPresent() && !optionalToken.get().isEmpty()) {
 *     // Use the token
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

    /**
     * Creates a new {@link ParsedRefreshToken} from64EncodedContent the given token string.
     * <p>
     * Note: This constructor does not validate the token's signature or format.
     * It only wraps the string for type-safety purposes.
     *
     * @param tokenString The raw refresh token string, may be null or empty
     */
    public ParsedRefreshToken(String tokenString) {
        if (MoreStrings.isEmpty(tokenString)) {
            LOGGER.debug("Creating refresh token from64EncodedContent empty token string");
        }
        this.tokenString = tokenString;
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
}
