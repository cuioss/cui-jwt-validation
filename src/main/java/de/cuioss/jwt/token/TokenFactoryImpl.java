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

import de.cuioss.jwt.token.util.MultiIssuerJwtParser;
import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

/**
 * Factory for creating and validating OAuth2/OpenID Connect tokens with multi-issuer support.
 * Provides a centralized way to create different types of tokens while handling token parsing
 * and validation through configurable token parsers.
 * <p>
 * Key features:
 * <ul>
 *   <li>Support for multiple token issuers</li>
 *   <li>Automatic parser selection based on token characteristics</li>
 *   <li>Creation of typed token instances ({@link ParsedAccessToken}, {@link ParsedIdToken}, {@link ParsedRefreshToken})</li>
 *   <li>Thread-safe token creation and validation</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * TokenFactoryImpl factory = TokenFactoryImpl.of(parser1, parser2);
 * Optional&lt;ParsedAccessToken&gt; token = factory.createAccessToken(tokenString);
 * </pre>
 * <p>
 * The factory uses {@link MultiIssuerJwtParser} internally to manage multiple token parsers
 * and select the appropriate one based on the token's issuer and format.
 * <p>
 * See specification: {@code doc/specification/technical-components.adoc#_tokenfactory}
 * <p>
 * Implements requirement: {@code CUI-JWT-2: Token Representation}
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class TokenFactoryImpl {

    private static final CuiLogger LOGGER = new CuiLogger(TokenFactoryImpl.class);

    private final MultiIssuerJwtParser tokenParser;

    /**
     * Creates a new token factory using the given parser.
     *
     * @param tokenParser The parser to use for token validation, must not be null
     * @return A new TokenFactoryImpl instance
     */
    public static TokenFactoryImpl of(@NonNull JwksAwareTokenParserImpl... tokenParser) {
        Preconditions.checkArgument(tokenParser.length > 0, "tokenParser must be set");
        var builder = MultiIssuerJwtParser.builder();
        for (JwksAwareTokenParserImpl parser : tokenParser) {
            builder.addParser(parser);
        }
        var factory = new TokenFactoryImpl(builder.build());
        LOGGER.debug("Created TokenFactoryImpl with %s parser(s)", tokenParser.length);
        return factory;
    }

    /**
     * Creates an access token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed access token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<ParsedAccessToken> createAccessToken(@NonNull String tokenString) {
        LOGGER.debug("Creating access token");
        var parser = tokenParser.getParserForToken(tokenString);
        if (parser.isPresent()) {
            LOGGER.debug("Found parser for token, attempting to create access token");
            return ParsedAccessToken.fromTokenString(tokenString, parser.get());
        }
        LOGGER.debug("No suitable parser found for token");
        return Optional.empty();
    }

    /**
     * Creates an ID token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed ID token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<ParsedIdToken> createIdToken(@NonNull String tokenString) {
        LOGGER.debug("Creating ID token");
        var parser = tokenParser.getParserForToken(tokenString);
        if (parser.isPresent()) {
            LOGGER.debug("Found parser for token, attempting to create ID token");
            return ParsedIdToken.fromTokenString(tokenString, parser.get());
        }
        LOGGER.debug("No suitable parser found for token");
        return Optional.empty();
    }

    /**
     * Creates a refresh token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed refresh token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<ParsedRefreshToken> createRefreshToken(@NonNull String tokenString) {
        LOGGER.debug("Creating refresh token");
        return tokenParser.getParserForToken(tokenString)
                .map(parser -> {
                    LOGGER.debug("Found parser for token, creating refresh token");
                    return ParsedRefreshToken.fromTokenString(tokenString);
                });
    }
}
