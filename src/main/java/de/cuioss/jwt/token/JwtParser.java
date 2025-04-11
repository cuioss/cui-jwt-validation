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
import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.jwt.token.jwks.key.KeyInfo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import lombok.NonNull;

import java.util.Optional;

/**
 * Interface for JWT token parsing, validation, and creation.
 * Defines the contract for components that can parse, validate, and create JWT tokens,
 * with support for issuer-specific validation and token type-specific creation.
 * <p>
 * Key features:
 * <ul>
 *   <li>Token parsing and validation</li>
 *   <li>Issuer-specific validation</li>
 *   <li>Support for multiple token issuers</li>
 *   <li>Creation of typed tokens (Access, ID, Refresh)</li>
 * </ul>
 * <p>
 * Implementations of this interface should handle:
 * <ul>
 *   <li>Signature verification</li>
 *   <li>Token format validation</li>
 *   <li>Claim validation</li>
 *   <li>Key management</li>
 *   <li>Token creation for different token types</li>
 * </ul>
 * <p>
 * Implements requirement: {@code CUI-JWT-1.3: Signature Validation}
 * <p>
 * For more details on the requirements, see the
 * <a href="../../../../../../doc/specification/technical-components.adoc">Technical Components Specification</a>.
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
     * Creates an access token from the given token string and key information.
     *
     * @param tokenString the token string
     * @param keyInfo the key information for token validation
     * @return an Optional containing the parsed access token if valid, or empty otherwise
     */
    Optional<ParsedAccessToken> createAccessToken(@NonNull String tokenString, @NonNull KeyInfo keyInfo);

    /**
     * Creates an access token from the given token string with an associated email.
     *
     * @param tokenString the token string
     * @param keyInfo the key information for token validation
     * @param email the email to associate with the token
     * @return an Optional containing the parsed access token if valid, or empty otherwise
     */
    Optional<ParsedAccessToken> createAccessToken(@NonNull String tokenString, @NonNull KeyInfo keyInfo, String email);

    /**
     * Creates an ID token from the given token string.
     *
     * @param tokenString the token string
     * @param keyInfo the key information for token validation
     * @return an Optional containing the parsed ID token if valid, or empty otherwise
     */
    Optional<ParsedIdToken> createIdToken(@NonNull String tokenString, @NonNull KeyInfo keyInfo);

    /**
     * Creates a refresh token from the given token string.
     *
     * @param tokenString the token string
     * @param keyInfo the key information for token validation (may be null for opaque tokens)
     * @return an Optional containing the parsed refresh token if valid, or empty otherwise
     */
    Optional<ParsedRefreshToken> createRefreshToken(@NonNull String tokenString, KeyInfo keyInfo);

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

    /**
     * Gets the JWKS loader used by this parser.
     * 
     * @return the JWKS loader
     */
    default JwksLoader getJwksLoader() {
        throw new UnsupportedOperationException("JWKS loader not supported by this implementation");
    }
}
