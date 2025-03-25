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
import de.cuioss.jwt.token.util.MultiIssuerJwtParser;
import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import io.jsonwebtoken.JwtException;
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
 *   <li>Configurable token size limits</li>
 * </ul>
 * <p>
 * Basic usage example:
 * <pre>
 * TokenFactory factory = TokenFactory.builder()
 *     .addParser(parser1)
 *     .addParser(parser2)
 *     .build();
 * Optional&lt;ParsedAccessToken&gt; token = factory.createAccessToken(tokenString);
 * </pre>
 * <p>
 * Advanced usage with custom token size limits:
 * <pre>
 * TokenFactory factory = TokenFactory.builder()
 *     .addParser(parser1)
 *     .addParser(parser2)
 *     .maxTokenSize(8 * 1024)  // 8KB
 *     .maxPayloadSize(4 * 1024)  // 4KB
 *     .build();
 * Optional&lt;ParsedAccessToken&gt; token = factory.createAccessToken(tokenString);
 * </pre>
 * <p>
 * The factory uses {@link MultiIssuerJwtParser} internally to manage multiple token parsers
 * and select the appropriate one based on the token's issuer and format.
 * <p>
 * Implements requirement: {@code CUI-JWT-2: Token Representation}
 * <p>
 * For more details on the requirements, see the
 * <a href="../../../../../../../doc/specification/technical-components.adoc">Technical Components Specification</a>.
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class TokenFactory {

    private static final CuiLogger LOGGER = new CuiLogger(TokenFactory.class);
    public static final String NO_SUITABLE_PARSER_FOUND_FOR_TOKEN = "No suitable parser found for token";

    private final MultiIssuerJwtParser tokenParser;


    /**
     * Creates a new builder for {@link TokenFactory}
     *
     * @return a new {@link Builder} instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link TokenFactory}
     */
    public static class Builder {
        private final java.util.List<JwksAwareTokenParserImpl> parsers = new java.util.ArrayList<>();
        private Integer maxTokenSize;
        private Integer maxPayloadSize;

        /**
         * Adds a parser for a specific issuer
         *
         * @param parser the parser for that issuer
         * @return this builder instance
         */
        public Builder addParser(@NonNull JwksAwareTokenParserImpl parser) {
            parsers.add(parser);
            return this;
        }

        /**
         * Sets the maximum token size in bytes
         *
         * @param maxTokenSize the maximum token size in bytes
         * @return this builder instance
         */
        public Builder maxTokenSize(int maxTokenSize) {
            this.maxTokenSize = maxTokenSize;
            return this;
        }

        /**
         * Sets the maximum payload size in bytes
         *
         * @param maxPayloadSize the maximum payload size in bytes
         * @return this builder instance
         */
        public Builder maxPayloadSize(int maxPayloadSize) {
            this.maxPayloadSize = maxPayloadSize;
            return this;
        }

        /**
         * Builds the {@link TokenFactory}
         *
         * @return a new instance of {@link TokenFactory}
         */
        public TokenFactory build() {
            Preconditions.checkArgument(!parsers.isEmpty(), "At least one parser must be added");

            // Create MultiIssuerJwtParser builder
            MultiIssuerJwtParser.Builder multiIssuerBuilder = MultiIssuerJwtParser.builder();

            // Configure token size limits if provided
            if (maxTokenSize != null || maxPayloadSize != null) {
                multiIssuerBuilder.configureInspectionParser(builder -> {
                    if (maxTokenSize != null) {
                        builder.maxTokenSize(maxTokenSize);
                    }
                    if (maxPayloadSize != null) {
                        builder.maxPayloadSize(maxPayloadSize);
                    }
                });
            }

            // Add parsers
            for (JwksAwareTokenParserImpl parser : parsers) {
                multiIssuerBuilder.addParser(parser);
            }

            // Build MultiIssuerJwtParser and TokenFactory
            var factory = new TokenFactory(multiIssuerBuilder.build());
            LOGGER.debug("Created TokenFactory with %s parser(s)", parsers.size());
            return factory;
        }
    }

    /**
     * Creates a JsonWebToken from the given token string using the appropriate parser.
     * This method handles token validation and parsing errors.
     *
     * @param tokenString The token string to parse, must not be null
     * @param parser      The parser to use for parsing the token
     * @return An Optional containing the parsed JsonWebToken, or empty if parsing failed
     */
    private Optional<JsonWebToken> createJsonWebToken(String tokenString, JwtParser parser) {
        LOGGER.trace("Parsing token '%s'", tokenString);
        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }
        try {
            return parser.parse(tokenString);
        } catch (JwtException e) {
            LOGGER.warn(e, JWTTokenLogMessages.WARN.COULD_NOT_PARSE_TOKEN.format(e.getMessage()));
            LOGGER.trace("Offending token '%s'", tokenString);
            return Optional.empty();
        }
    }

    /**
     * Creates an access token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed access token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<ParsedAccessToken> createAccessToken(@NonNull String tokenString) {
        LOGGER.debug("Creating access token");
        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }
        var parser = tokenParser.getParserForToken(tokenString);
        if (parser.isPresent()) {
            LOGGER.debug("Found parser for token, attempting to create access token");
            return createJsonWebToken(tokenString, parser.get())
                    .map(jwt -> new ParsedAccessToken(jwt, null));
        }
        LOGGER.debug(NO_SUITABLE_PARSER_FOUND_FOR_TOKEN);
        return Optional.empty();
    }

    /**
     * Creates an access token from the given token string with an associated email.
     *
     * @param tokenString The token string to parse, must not be null
     * @param email       The email address associated with this token, may be null
     * @return The parsed access token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<ParsedAccessToken> createAccessToken(@NonNull String tokenString, String email) {
        LOGGER.debug("Creating access token with email");
        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }
        var parser = tokenParser.getParserForToken(tokenString);
        if (parser.isPresent()) {
            LOGGER.debug("Found parser for token, attempting to create access token with email");
            return createJsonWebToken(tokenString, parser.get())
                    .map(jwt -> new ParsedAccessToken(jwt, email));
        }
        LOGGER.debug(NO_SUITABLE_PARSER_FOUND_FOR_TOKEN);
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
        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }
        var parser = tokenParser.getParserForToken(tokenString);
        if (parser.isPresent()) {
            LOGGER.debug("Found parser for token, attempting to create ID token");
            return createJsonWebToken(tokenString, parser.get())
                    .map(ParsedIdToken::new);
        }
        LOGGER.debug(NO_SUITABLE_PARSER_FOUND_FOR_TOKEN);
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
                    return new ParsedRefreshToken(tokenString);
                });
    }
}
