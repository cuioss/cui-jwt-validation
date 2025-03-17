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
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;

import java.util.Optional;

/**
 * Interface for JWT token parsing and validation.
 * Defines the contract for components that can parse and validate JWT tokens,
 * with support for issuer-specific validation.
 * <p>
 * Key features:
 * <ul>
 *   <li>Token parsing and validation</li>
 *   <li>Issuer-specific validation</li>
 *   <li>Support for multiple token issuers</li>
 * </ul>
 * <p>
 * Implementations of this interface should handle:
 * <ul>
 *   <li>Signature verification</li>
 *   <li>Token format validation</li>
 *   <li>Claim validation</li>
 *   <li>Key management</li>
 * </ul>
 * <p>
 * See specification: {@code doc/specification/technical-components.adoc#_jwtparser}
 * <p>
 * Implements requirement: {@code CUI-JWT-1.3: Signature Validation}
 *
 * @author Oliver Wolff
 */
public interface JwtParser {

    /**
     * Parses and validates a JWT token.
     *
     * @param token the JWT token string to parse and validate
     * @return an Optional containing the parsed JWT claims if validation succeeds,
     *         or empty if the token is invalid or cannot be parsed
     * @throws JwtException if an error occurs during parsing or validation
     */
    Optional<Jws<Claims>> parseToken(String token) throws JwtException;

    /**
     * Parses and validates a JWT token, returning a JsonWebToken.
     * This method is provided for compatibility with the existing code that uses
     * the JsonWebToken interface.
     *
     * @param token the JWT token string to parse and validate
     * @return an Optional containing the parsed JWT token if validation succeeds,
     *         or empty if the token is invalid or cannot be parsed
     * @throws JwtException if an error occurs during parsing or validation
     */
    Optional<JsonWebToken> parse(String token) throws JwtException;

    /**
     * Checks if this parser supports the given issuer.
     *
     * @param issuer the issuer to check
     * @return true if this parser supports the given issuer, false otherwise
     */
    boolean supportsIssuer(String issuer);

    /**
     * Gets the issuer supported by this parser.
     *
     * @return the issuer URL
     */
    String getIssuer();
}
