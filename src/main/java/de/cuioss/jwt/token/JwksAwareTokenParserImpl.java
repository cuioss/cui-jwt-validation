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
import de.cuioss.jwt.token.adapter.JwtAdapter;
import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.jwt.token.jwks.KeyInfo;
import de.cuioss.jwt.token.security.AlgorithmPreferences;
import de.cuioss.jwt.token.util.DecodedJwt;
import de.cuioss.jwt.token.util.NonValidatingJwtParser;
import de.cuioss.tools.logging.CuiLogger;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

import java.security.Key;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static de.cuioss.jwt.token.JWTTokenLogMessages.INFO;
import static de.cuioss.jwt.token.JWTTokenLogMessages.WARN;

/**
 * JWT parser implementation with support for remote JWKS (JSON Web Key Set) loading.
 * This parser extends the standard JJWT functionality by adding the ability
 * to fetch and manage public keys from a JWKS endpoint for token signature verification.
 * <p>
 * Key features:
 * <ul>
 *   <li>Remote JWKS endpoint configuration</li>
 *   <li>Automatic key refresh support</li>
 *   <li>TLS certificate configuration for secure key loading</li>
 *   <li>Issuer-based token validation</li>
 * </ul>
 * <p>
 * The parser can be configured using the constructor:
 * <pre>
 * JwksLoader jwksLoader = JwksLoaderFactory.createHttpLoader(
 *     "https://auth.example.com/.well-known/jwks.json",
 *     60,
 *     null);
 * JwksAwareTokenParserImpl parser = new JwksAwareTokenParserImpl(
 *     jwksLoader,
 *     "https://auth.example.com");
 * </pre>
 * <p>
 * This implementation is thread-safe and handles automatic key rotation
 * based on the configured refresh interval.
 * <p>
 * Implements requirement: {@code CUI-JWT-1.3: Signature Validation}
 * <p>
 * For more details on the requirements, see the
 * <a href="../../../../../../doc/specification/technical-components.adoc">Technical Components Specification</a>.
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class JwksAwareTokenParserImpl implements de.cuioss.jwt.token.JwtParser {

    private static final CuiLogger LOGGER = new CuiLogger(JwksAwareTokenParserImpl.class);
    public static final int DEFAULT_REFRESH_INTERVAL = 180;

    private final JwtParser jwtParser;
    private final JwksLoader jwksLoader;
    private final ClaimValidator claimValidator;
    private final AlgorithmPreferences algorithmPreferences;

    @Getter
    private final String issuer;

    /**
     * Constructor for JwksAwareTokenParserImpl.
     *
     * @param jwksLoader the JWKS loader, must not be null
     * @param issuer     the issuer, must not be null
     */
    public JwksAwareTokenParserImpl(@NonNull JwksLoader jwksLoader, @NonNull String issuer) {
        this(jwksLoader, issuer, new AlgorithmPreferences());
    }

    /**
     * Constructor for JwksAwareTokenParserImpl with custom algorithm preferences.
     *
     * @param jwksLoader           the JWKS loader, must not be null
     * @param issuer               the issuer, must not be null
     * @param algorithmPreferences the algorithm preferences, must not be null
     */
    public JwksAwareTokenParserImpl(@NonNull JwksLoader jwksLoader, @NonNull String issuer,
                                    @NonNull AlgorithmPreferences algorithmPreferences) {
        this.jwksLoader = jwksLoader;
        this.issuer = issuer;
        this.algorithmPreferences = algorithmPreferences;
        this.jwtParser = Jwts.parserBuilder()
                .setAllowedClockSkewSeconds(30)
                .requireIssuer(issuer)
                .build();
        this.tokenParser = NonValidatingJwtParser.builder().build();
        this.claimValidator = new ClaimValidator(issuer);

        // Log the initialization
        LOGGER.info(INFO.CONFIGURED_JWKS.format(
                jwksLoader.toString(),
                DEFAULT_REFRESH_INTERVAL,
                issuer));
    }

    /**
     * The JWT token parser used for decoding tokens.
     */
    private final de.cuioss.jwt.token.util.NonValidatingJwtParser tokenParser;

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<Jws<Claims>> parseToken(String token) throws JwtException {
        try {
            // Use the NonValidatingJwtParser to decode the token
            Optional<DecodedJwt> decodedJwt = tokenParser.decode(token);
            if (decodedJwt.isEmpty()) {
                LOGGER.warn(WARN.FAILED_TO_DECODE_JWT::format);
                return Optional.empty();
            }

            // Extract algorithm from header
            String requestedAlg = decodedJwt.get().getAlg().orElse("RS256"); // Default to RS256 if not specified
            LOGGER.debug("Token requests algorithm: %s", requestedAlg);

            // Check if the algorithm is supported
            if (!algorithmPreferences.isSupported(requestedAlg)) {
                LOGGER.warn(WARN.UNSUPPORTED_ALGORITHM.format(requestedAlg));
                return Optional.empty();
            }

            // Get key information
            Optional<KeyInfo> keyInfo = getKeyInfo(decodedJwt.get(), requestedAlg);
            if (keyInfo.isEmpty()) {
                return Optional.empty();
            }

            // Parse and validate the token
            return parseAndValidateToken(token, keyInfo.get());
        } catch (JwtException e) {
            LOGGER.warn(e, WARN.COULD_NOT_PARSE_TOKEN.format(e.getMessage()));
            LOGGER.trace("Offending token '%s'", token);
            return Optional.empty();
        } catch (Exception e) {
            LOGGER.warn(e, WARN.ERROR_PARSING_TOKEN.format(e.getMessage()));
            return Optional.empty();
        }
    }

    /**
     * Retrieves the key information based on the decoded JWT.
     * 
     * @param decodedJwt The decoded JWT
     * @param requestedAlg The requested algorithm
     * @return An Optional containing the KeyInfo if found, or empty if not found
     */
    private Optional<KeyInfo> getKeyInfo(DecodedJwt decodedJwt, String requestedAlg) {
        // Try to get key by ID first
        Optional<String> kidOption = decodedJwt.getKid();
        if (kidOption.isPresent()) {
            String kid = kidOption.get();
            Optional<KeyInfo> keyInfo = jwksLoader.getKeyInfo(kid);
            if (keyInfo.isEmpty()) {
                LOGGER.warn(WARN.KEY_NOT_FOUND.format(kid));
            }
            return keyInfo;
        }

        // If no key ID is present, try to find a key with the requested algorithm
        LOGGER.debug("No key ID found in token header, trying to find a key with algorithm: %s", requestedAlg);

        // Get all available keys
        List<KeyInfo> availableKeys = jwksLoader.getAllKeyInfos();
        if (availableKeys.isEmpty()) {
            LOGGER.warn(WARN.NO_KEYS_AVAILABLE::format);
            return Optional.empty();
        }

        // Filter keys by algorithm
        List<String> availableAlgorithms = availableKeys.stream()
                .map(KeyInfo::getAlgorithm)
                .collect(Collectors.toList());

        // Get the most preferred algorithm that is available
        Optional<String> preferredAlg = algorithmPreferences.getMostPreferredAlgorithm(availableAlgorithms);
        if (preferredAlg.isEmpty()) {
            LOGGER.warn(WARN.NO_SUPPORTED_ALGORITHM::format);
            return Optional.empty();
        }

        // Find a key with the preferred algorithm
        Optional<KeyInfo> keyInfo = availableKeys.stream()
                .filter(k -> preferredAlg.get().equals(k.getAlgorithm()))
                .findFirst();

        if (keyInfo.isEmpty()) {
            LOGGER.warn(WARN.NO_KEY_FOR_ALGORITHM.format(preferredAlg.get()));
        }

        return keyInfo;
    }

    /**
     * Parses and validates the token using the provided key information.
     * 
     * @param token The token to parse
     * @param keyInfo The key information to use for parsing
     * @return An Optional containing the parsed JWT if valid, or empty if invalid
     */
    private Optional<Jws<Claims>> parseAndValidateToken(String token, KeyInfo keyInfo) {
        Key key = keyInfo.getKey();
        String algorithm = keyInfo.getAlgorithm();
        LOGGER.debug("Using key with algorithm: %s", algorithm);

        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);

            // Validate all required claims
            if (!claimValidator.validateClaims(jws)) {
                return Optional.empty();
            }

            return Optional.of(jws);
        } catch (JwtException e) {
            LOGGER.warn(e, WARN.COULD_NOT_PARSE_TOKEN.format(e.getMessage()));
            LOGGER.trace("Offending token '%s'", token);
            return Optional.empty();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<JsonWebToken> parse(String token) throws JwtException {
        LOGGER.debug("Parsing token to JsonWebToken");
        return parseToken(token).map(jws -> new JwtAdapter(jws, token));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supportsIssuer(String issuer) {
        return this.issuer.equals(issuer);
    }


}
