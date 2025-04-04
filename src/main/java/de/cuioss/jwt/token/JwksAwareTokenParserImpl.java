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
import de.cuioss.jwt.token.jwks.key.KeyInfo;
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

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

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
 *   <li>Audience validation for protecting against token misuse</li>
 *   <li>Client ID (azp claim) validation for preventing client confusion attacks</li>
 * </ul>
 * <p>
 * The parser can be configured using the builder pattern:
 * <pre>
 * JwksLoader jwksLoader = JwksLoaderFactory.createHttpLoader(
 *     "https://auth.example.com/.well-known/jwks.json",
 *     60,
 *     null);
 * JwksAwareTokenParserImpl parser = JwksAwareTokenParserImpl.builder()
 *     .jwksLoader(jwksLoader)
 *     .issuer("https://auth.example.com")
 *     .expectedAudience(Set.of("my-client-id"))
 *     .expectedClientId("my-client-id")
 *     .build();
 * </pre>
 * <p>
 * This implementation is thread-safe and handles automatic key rotation
 * based on the configured refresh interval.
 * <p>
 * <strong>Security Note:</strong> To protect against client confusion attacks, it is strongly
 * recommended to set both the expected audience and the expected client ID. This ensures that
 * tokens issued for one client cannot be used with a different client.
 * <p>
 * Implements requirement: {@code CUI-JWT-1.3: Signature Validation} and {@code CUI-JWT-8.4: Claims Validation}
 * <p>
 * For more details on the requirements, see the
 * <a href="../../../../../../doc/specification/technical-components.adoc">Technical Components Specification</a>.
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 */
@SuppressWarnings("JavadocLinkAsPlainText")
@ToString
@EqualsAndHashCode
public class JwksAwareTokenParserImpl implements de.cuioss.jwt.token.JwtParser {

    private static final CuiLogger LOGGER = new CuiLogger(JwksAwareTokenParserImpl.class);
    public static final int DEFAULT_REFRESH_INTERVAL = 180;

    /**
     * Builder for creating JwksAwareTokenParserImpl instances.
     */
    public static class Builder {
        private JwksLoader jwksLoader;
        private String issuer;
        private AlgorithmPreferences algorithmPreferences;
        private Set<String> expectedAudience;
        private String expectedClientId;

        /**
         * Sets the JWKS loader.
         *
         * @param jwksLoader the JWKS loader
         * @return this builder instance
         */
        public Builder jwksLoader(@NonNull JwksLoader jwksLoader) {
            this.jwksLoader = jwksLoader;
            return this;
        }

        /**
         * Sets the issuer.
         *
         * @param issuer the issuer
         * @return this builder instance
         */
        public Builder issuer(@NonNull String issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         * Sets the algorithm preferences.
         *
         * @param algorithmPreferences the algorithm preferences
         * @return this builder instance
         */
        public Builder algorithmPreferences(@NonNull AlgorithmPreferences algorithmPreferences) {
            this.algorithmPreferences = algorithmPreferences;
            return this;
        }

        /**
         * Sets the expected audience.
         *
         * @param expectedAudience the expected audience
         * @return this builder instance
         */
        public Builder expectedAudience(Set<String> expectedAudience) {
            this.expectedAudience = expectedAudience;
            return this;
        }
        
        /**
         * Sets the expected client ID for azp claim validation.
         * <p>
         * The authorized party (azp) claim identifies the client that the token was issued for.
         * Validating this claim prevents client confusion attacks where tokens issued for one client
         * are used with a different client.
         *
         * @param expectedClientId the expected client ID
         * @return this builder instance
         */
        public Builder expectedClientId(String expectedClientId) {
            this.expectedClientId = expectedClientId;
            return this;
        }

        /**
         * Builds a new JwksAwareTokenParserImpl instance.
         *
         * @return a new JwksAwareTokenParserImpl instance
         * @throws IllegalArgumentException if jwksLoader or issuer is null
         */
        public JwksAwareTokenParserImpl build() {
            if (jwksLoader == null) {
                throw new IllegalArgumentException("JWKS loader must not be null");
            }
            if (issuer == null) {
                throw new IllegalArgumentException("Issuer must not be null");
            }

            AlgorithmPreferences prefs = algorithmPreferences != null ?
                    algorithmPreferences : new AlgorithmPreferences();

            return new JwksAwareTokenParserImpl(jwksLoader, issuer, prefs, expectedAudience, expectedClientId);
        }
    }

    /**
     * Creates a new builder for JwksAwareTokenParserImpl.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

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
        this(jwksLoader, issuer, algorithmPreferences, null);
    }

    /**
     * Constructor for JwksAwareTokenParserImpl with custom algorithm preferences and expected audience.
     *
     * @param jwksLoader           the JWKS loader, must not be null
     * @param issuer               the issuer, must not be null
     * @param algorithmPreferences the algorithm preferences, must not be null
     * @param expectedAudience     the expected audience, may be null if no audience validation is required
     */
    public JwksAwareTokenParserImpl(@NonNull JwksLoader jwksLoader, @NonNull String issuer,
            @NonNull AlgorithmPreferences algorithmPreferences,
            Set<String> expectedAudience) {
        this(jwksLoader, issuer, algorithmPreferences, expectedAudience, null);
    }
    
    /**
     * Constructor for JwksAwareTokenParserImpl with custom algorithm preferences, expected audience,
     * and expected client ID.
     *
     * @param jwksLoader           the JWKS loader, must not be null
     * @param issuer               the issuer, must not be null
     * @param algorithmPreferences the algorithm preferences, must not be null
     * @param expectedAudience     the expected audience, may be null if no audience validation is required
     * @param expectedClientId     the expected client ID, may be null if no client ID validation is required
     */
    public JwksAwareTokenParserImpl(@NonNull JwksLoader jwksLoader, @NonNull String issuer,
            @NonNull AlgorithmPreferences algorithmPreferences,
            Set<String> expectedAudience,
            String expectedClientId) {
        this.jwksLoader = jwksLoader;
        this.issuer = issuer;
        this.algorithmPreferences = algorithmPreferences;
        this.jwtParser = Jwts.parser()
                .clockSkewSeconds(30)
                .requireIssuer(issuer)
                .build();
        this.tokenParser = NonValidatingJwtParser.builder().build();
        this.claimValidator = new ClaimValidator(issuer, expectedAudience, expectedClientId);

        // Log the initialization
        LOGGER.info(INFO.CONFIGURED_JWKS.format(
                jwksLoader.toString(),
                DEFAULT_REFRESH_INTERVAL,
                issuer));
    }

    /**
     * The JWT token parser used for decoding tokens.
     */
    private final NonValidatingJwtParser tokenParser;

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

            // Extract algorithm from64EncodedContent header
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
     * @param decodedJwt   The decoded JWT
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
                .toList();

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
     * @param token   The token to parse
     * @param keyInfo The key information to use for parsing
     * @return An Optional containing the parsed JWT if valid, or empty if invalid
     */
    private Optional<Jws<Claims>> parseAndValidateToken(String token, KeyInfo keyInfo) {
        PublicKey key = keyInfo.getKey();
        String algorithm = keyInfo.getAlgorithm();
        LOGGER.debug("Using key with algorithm: %s", algorithm);

        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);

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
