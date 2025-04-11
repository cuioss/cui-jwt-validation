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
package de.cuioss.jwt.token.adapter.jjwt;

import de.cuioss.jwt.token.JWTTokenLogMessages;
import de.cuioss.jwt.token.JwtParser;
import de.cuioss.jwt.token.ParsedAccessToken;
import de.cuioss.jwt.token.ParsedIdToken;
import de.cuioss.jwt.token.ParsedRefreshToken;
import de.cuioss.jwt.token.adapter.JsonWebToken;
import de.cuioss.jwt.token.util.MultiIssuerJwtParser;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import io.jsonwebtoken.JwtException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

/**
 * JJWT-specific utility class for token creation.
 * This class has helper methods to work with the JjwtAdapter.
 */
@RequiredArgsConstructor
public class JjwtTokenFactory {

    private static final CuiLogger LOGGER = new CuiLogger(JjwtTokenFactory.class);

    private final MultiIssuerJwtParser tokenParser;

    /**
     * Creates an access token from the given token string.
     *
     * @param tokenString the token string
     * @return an Optional containing the parsed access token if valid, or empty otherwise
     */
    public Optional<ParsedAccessToken> createAccessToken(@NonNull String tokenString) {
        return createAccessToken(tokenString, null);
    }

    /**
     * Creates an access token from the given token string with an associated email.
     *
     * @param tokenString the token string
     * @param email the email to associate with the token
     * @return an Optional containing the parsed access token if valid, or empty otherwise
     */
    public Optional<ParsedAccessToken> createAccessToken(@NonNull String tokenString, String email) {
        LOGGER.debug("Creating access token");

        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }

        return tokenParser.getParserForToken(tokenString)
                .flatMap(parser -> createJjwtAdapter(tokenString, parser))
                .map(adapter -> new ParsedAccessToken(adapter, email));
    }

    /**
     * Creates an ID token from the given token string.
     *
     * @param tokenString the token string
     * @return an Optional containing the parsed ID token if valid, or empty otherwise
     */
    public Optional<ParsedIdToken> createIdToken(@NonNull String tokenString) {
        LOGGER.debug("Creating ID token");

        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }

        return tokenParser.getParserForToken(tokenString)
                .flatMap(parser -> createJjwtAdapter(tokenString, parser))
                .map(ParsedIdToken::new);
    }

    /**
     * Creates a refresh token from the given token string.
     *
     * @param tokenString the token string
     * @return an Optional containing the parsed refresh token if valid, or empty otherwise
     */
    public Optional<ParsedRefreshToken> createRefreshToken(@NonNull String tokenString) {
        LOGGER.debug("Creating refresh token");

        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }

        // Get parser for token
        var parserOption = tokenParser.getParserForToken(tokenString);
        if (parserOption.isEmpty()) {
            LOGGER.debug("No suitable parser found for token");
            return Optional.empty();
        }

        JwtParser parser = parserOption.get();

        // Try to parse as JWT token silently (without logging warnings)
        Optional<JsonWebToken> jwtOpt = createJjwtAdapter(tokenString, parser);

        if (jwtOpt.isPresent()) {
            // Token is a valid JWT
            JsonWebToken jwt = jwtOpt.get();
            LOGGER.debug("Creating refresh token with JWT content");
            return Optional.of(new ParsedRefreshToken(tokenString, jwt));
        } else {
            // Token is not a valid JWT, treat as opaque
            LOGGER.debug("Creating refresh token as opaque string");
            return Optional.of(new ParsedRefreshToken(tokenString));
        }
    }

    /**
     * Creates a JsonWebToken from the given token string and parser.
     *
     * @param tokenString the token string
     * @param parser the parser
     * @return an Optional containing the JsonWebToken, or empty if parsing failed
     */
    private Optional<JsonWebToken> createJjwtAdapter(String tokenString, JwtParser parser) {
        try {
            return parser.parse(tokenString);
        } catch (JwtException e) {
            LOGGER.warn(e, JWTTokenLogMessages.WARN.COULD_NOT_PARSE_TOKEN.format(e.getMessage()));
            return Optional.empty();
        }
    }
}