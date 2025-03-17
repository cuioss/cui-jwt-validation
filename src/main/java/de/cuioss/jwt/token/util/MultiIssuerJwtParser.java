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
package de.cuioss.jwt.token.util;

import de.cuioss.jwt.token.JwksAwareTokenParserImpl;
import de.cuioss.jwt.token.JwtParser;
import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Manages multiple JWT token parsers for different token issuers in a multi-tenant environment.
 * This class provides functionality to inspect JWT tokens, determine their issuer, and select
 * the appropriate parser based on the issuer information.
 * <p>
 * Key features:
 * <ul>
 *   <li>Multi-issuer support for token validation</li>
 *   <li>Safe token inspection without signature validation</li>
 *   <li>Dynamic parser selection based on token issuer</li>
 *   <li>Thread-safe implementation</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * MultiIssuerJwtParser parser = MultiIssuerJwtParser.builder()
 *     .addParser(issuer1Parser)
 *     .addParser(issuer2Parser)
 *     .build();
 * 
 * Optional&lt;JwtParser&gt; selectedParser = parser.getParserForToken(tokenString);
 * </pre>
 * <p>
 * The class uses {@link NonValidatingJwtTokenParser} internally for initial token inspection
 * to determine the issuer before selecting the appropriate validating parser.
 * <p>
 * See specification: {@code doc/specification/technical-components.adoc#_multiissuertokenparser}
 * <p>
 * Implements requirement: {@code CUI-JWT-3: Multi-Issuer Support}
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class MultiIssuerJwtParser {

    private static final CuiLogger LOGGER = new CuiLogger(MultiIssuerJwtParser.class);

    private final Map<String, JwtParser> issuerToParser;
    private final NonValidatingJwtParser inspectionParser;

    /**
     * Constructor taking a map of issuer URLs to their corresponding parsers.
     *
     * @param issuerToParser Map containing issuer URLs as keys and their corresponding
     *                       {@link JwtParser} instances as values. Must not be null.
     */
    public MultiIssuerJwtParser(@NonNull Map<String, JwtParser> issuerToParser) {
        this.issuerToParser = new HashMap<>(issuerToParser);
        this.inspectionParser = new NonValidatingJwtParser();
        LOGGER.debug("Initialized MultiIssuerJwtParser with %s parser(s)", issuerToParser.size());
    }

    /**
     * Creates a new builder for {@link MultiIssuerJwtParser}
     *
     * @return a new {@link Builder} instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Inspects a JWT token to determine its issuer without validating the signature.
     *
     * @param token the JWT token to inspect, must not be null
     * @return the issuer of the token if present
     */
    public Optional<String> extractIssuer(@NonNull String token) {
        LOGGER.debug("Extracting issuer from token");
        var issuer = inspectionParser.extractIssuer(token);
        LOGGER.debug("Extracted issuer: %s", issuer.orElse("<none>"));
        return issuer;
    }

    /**
     * Retrieves the appropriate {@link JwtParser} for a given issuer.
     *
     * @param issuer the issuer URL to find the parser for
     * @return an Optional containing the parser if found, empty otherwise
     */
    public Optional<JwtParser> getParserForIssuer(@NonNull String issuer) {
        LOGGER.debug("Looking up parser for issuer: %s", issuer);
        var parser = Optional.ofNullable(issuerToParser.get(issuer));
        if (parser.isEmpty()) {
            LOGGER.debug("No parser found for issuer: %s", issuer);
        }
        return parser;
    }

    /**
     * Retrieves the appropriate {@link JwtParser} for a given token by first extracting
     * its issuer.
     *
     * @param token the JWT token to find the parser for
     * @return an Optional containing the parser if found, empty otherwise
     */
    public Optional<JwtParser> getParserForToken(@NonNull String token) {
        LOGGER.debug("Getting parser for token");
        return extractIssuer(token).flatMap(this::getParserForIssuer);
    }

    /**
     * Builder for {@link MultiIssuerJwtParser}
     */
    public static class Builder {
        private final Map<String, JwtParser> issuerToParser = new HashMap<>();

        /**
         * Adds a parser for a specific issuer
         *
         * @param parser the parser for that issuer
         * @return this builder instance
         */
        public Builder addParser(@NonNull JwksAwareTokenParserImpl parser) {
            LOGGER.debug("Adding parser for issuer: %s", parser.getIssuer());
            issuerToParser.put(parser.getIssuer(), parser);
            return this;
        }

        /**
         * Builds the {@link MultiIssuerJwtParser}
         *
         * @return a new instance of {@link MultiIssuerJwtParser}
         */
        public MultiIssuerJwtParser build() {
            return new MultiIssuerJwtParser(issuerToParser);
        }
    }
}
