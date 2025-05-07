/*
 * Copyright 2025 the original author or authors.
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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.domain.token.IdTokenContent;
import de.cuioss.jwt.validation.domain.token.RefreshTokenContent;
import de.cuioss.jwt.validation.domain.token.TokenContent;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.pipeline.DecodedJwt;
import de.cuioss.jwt.validation.pipeline.NonValidatingJwtParser;
import de.cuioss.jwt.validation.pipeline.TokenBuilder;
import de.cuioss.jwt.validation.pipeline.TokenClaimValidator;
import de.cuioss.jwt.validation.pipeline.TokenHeaderValidator;
import de.cuioss.jwt.validation.pipeline.TokenSignatureValidator;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.Getter;
import lombok.NonNull;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Main entry point for creating and validating JWT tokens.
 * <p>
 * This class provides methods for creating different types of tokens from
 * JWT strings, handling the validation and parsing process.
 * <p>
 * The validator uses a pipeline approach to validate tokens:
 * <ol>
 *   <li>Basic format validation</li>
 *   <li>Issuer validation</li>
 *   <li>Header validation</li>
 *   <li>Signature validation</li>
 *   <li>Token building</li>
 *   <li>Claim validation</li>
 * </ol>
 * <p>
 * This class is thread-safe after construction.
 * All validation methods can be called concurrently from multiple threads.
 * <p>
 * Usage example:
 * <pre>
 * // Configure HTTP-based JWKS loading
 * HttpJwksLoaderConfig httpConfig = HttpJwksLoaderConfig.builder()
 *     .jwksUrl("https://example.com/.well-known/jwks.json")
 *     .refreshIntervalSeconds(60)
 *     .build();
 *
 * // Create an issuer configuration
 * IssuerConfig issuerConfig = IssuerConfig.builder()
 *     .issuer("https://example.com")
 *     .expectedAudience("my-client")
 *     .httpJwksLoaderConfig(httpConfig)
 *     .build();
 *
 * // Create the token validator
 * // The validator creates a SecurityEventCounter internally and passes it to all components
 * TokenValidator tokenValidator = new TokenValidator(
 *     ParserConfig.builder().build(),
 *     issuerConfig
 * );
 *
 * // Parse an access token
 * Optional&lt;AccessTokenContent&gt; accessToken = tokenValidator.createAccessToken(tokenString);
 *
 * // Parse an ID token
 * Optional&lt;IdTokenContent&gt; idToken = tokenValidator.createIdToken(tokenString);
 *
 * // Parse a refresh token
 * Optional&lt;RefreshTokenContent&gt; refreshToken = tokenValidator.createRefreshToken(tokenString);
 *
 * // Access the security event counter for monitoring
 * SecurityEventCounter securityEventCounter = tokenValidator.getSecurityEventCounter();
 * </pre>
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/Requirements.adoc#CUI-JWT-1">CUI-JWT-1: Token Parsing and Validation</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/Requirements.adoc#CUI-JWT-2">CUI-JWT-2: Token Representation</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/Requirements.adoc#CUI-JWT-3">CUI-JWT-3: Multi-Issuer Support</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/specification/technical-components.adoc#_tokenvalidator">Technical Components Specification</a>
 *
 * @since 1.0
 */
@SuppressWarnings("JavadocLinkAsPlainText")
public class TokenValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidator.class);

    private final NonValidatingJwtParser jwtParser;
    private final Map<String, IssuerConfig> issuerConfigMap;

    /**
     * Counter for security events that occur during token processing.
     * This counter is thread-safe and can be accessed from outside to monitor security events.
     */
    @Getter
    private final SecurityEventCounter securityEventCounter;

    /**
     * Creates a new TokenValidator with the given issuer configurations.
     * It is used for standard use cases where no special configuration is needed.
     *
     * @param issuerConfigs varargs of issuer configurations, must not be null
     */
    public TokenValidator(@NonNull IssuerConfig... issuerConfigs) {
        this(ParserConfig.builder().build(), issuerConfigs);
    }

    /**
     * Creates a new TokenValidator with the given issuer configurations and parser configuration.
     *
     * @param config        configuration for the parser, must not be null
     * @param issuerConfigs varargs of issuer configurations, must not be null and must contain at least one configuration
     */
    public TokenValidator(@NonNull ParserConfig config, @NonNull IssuerConfig... issuerConfigs) {

        // Initialize security event counter
        this.securityEventCounter = new SecurityEventCounter();

        // Initialize NonValidatingJwtParser with configuration
        this.jwtParser = NonValidatingJwtParser.builder()
                .config(config)
                .securityEventCounter(securityEventCounter)
                .build();

        // Initialize issuerConfigMap with issuers as keys
        this.issuerConfigMap = new HashMap<>();
        for (IssuerConfig issuerConfig : issuerConfigs) {
            // Initialize the JwksLoader with the SecurityEventCounter
            issuerConfig.initSecurityEventCounter(securityEventCounter);
            issuerConfigMap.put(issuerConfig.getIssuer(), issuerConfig);
        }

        LOGGER.debug("Created TokenValidator with %d issuer configurations", issuerConfigs.length);
        LOGGER.info(JWTValidationLogMessages.INFO.TOKEN_FACTORY_INITIALIZED.format(issuerConfigs.length));
    }

    /**
     * Creates an access token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed access token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<AccessTokenContent> createAccessToken(@NonNull String tokenString) {
        LOGGER.debug("Creating access token");
        Optional<AccessTokenContent> result = processTokenPipeline(
                tokenString,
                (decodedJwt, issuerConfig) -> new TokenBuilder(issuerConfig).createAccessToken(decodedJwt)
        );

        if (result.isPresent()) {
            LOGGER.debug(JWTValidationLogMessages.DEBUG.ACCESS_TOKEN_CREATED::format);
            securityEventCounter.increment(SecurityEventCounter.EventType.ACCESS_TOKEN_CREATED);
        }

        return result;
    }

    /**
     * Creates an ID token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed ID token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<IdTokenContent> createIdToken(@NonNull String tokenString) {
        LOGGER.debug("Creating ID token");
        Optional<IdTokenContent> result = processTokenPipeline(
                tokenString,
                (decodedJwt, issuerConfig) -> new TokenBuilder(issuerConfig).createIdToken(decodedJwt)
        );

        if (result.isPresent()) {
            LOGGER.debug(JWTValidationLogMessages.DEBUG.ID_TOKEN_CREATED::format);
            securityEventCounter.increment(SecurityEventCounter.EventType.ID_TOKEN_CREATED);
        }

        return result;
    }

    /**
     * Creates a refresh token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed refresh token, which may be empty if the token is invalid or no parser is found
     */
    @SuppressWarnings("java:S3655") // owolff: false positive: isPresent is checked
    public Optional<RefreshTokenContent> createRefreshToken(@NonNull String tokenString) {
        LOGGER.debug("Creating refresh token");
        // For refresh tokens, we don't need the full pipeline
        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_IS_EMPTY::format);
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
            return Optional.empty();
        }
        Map<String, ClaimValue> claims = Collections.emptyMap();
        var decoded = jwtParser.decode(tokenString, false);
        if (decoded.isPresent() && decoded.get().getBody().isPresent()) {
            LOGGER.debug("Adding claims, because of being a JWT");
            claims = TokenBuilder.extractClaimsForRefreshToken(decoded.get().getBody().get());
        }
        var refreshToken = new RefreshTokenContent(tokenString, claims);
        LOGGER.debug(JWTValidationLogMessages.DEBUG.REFRESH_TOKEN_CREATED::format);
        securityEventCounter.increment(SecurityEventCounter.EventType.REFRESH_TOKEN_CREATED);
        return Optional.of(refreshToken);
    }

    /**
     * Processes a token through the token pipeline.
     * <p>
     * This method implements an optimized token pipeline with early termination
     * for common failure cases. The token steps are ordered to fail fast:
     * 1. Basic token format validation (empty check, decoding)
     * 2. Issuer validation (presence and configuration lookup)
     * 3. Header validation (algorithm)
     * 4. Signature validation
     * 5. Token building
     * 6. Claim validation
     * <p>
     * Validators are only created if needed, avoiding unnecessary object creation
     * for invalid tokens.
     *
     * @param tokenString  the token string to process
     * @param tokenBuilder function to build the token from the decoded JWT and issuer config
     * @param <T>          the type of token to create
     * @return an Optional containing the validated token, or empty if validation fails
     */
    private <T extends TokenContent> Optional<T> processTokenPipeline(
            String tokenString,
            TokenBuilderFunction<T> tokenBuilder) {

        // 1. Basic token format validation - fail fast for empty tokens
        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_IS_EMPTY::format);
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
            return Optional.empty();
        }

        // 2. Decode the token - fail fast for malformed tokens
        Optional<DecodedJwt> decodedJwt = jwtParser.decode(tokenString);
        if (decodedJwt.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.FAILED_TO_DECODE_JWT::format);
            securityEventCounter.increment(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT);
            return Optional.empty();
        }

        // 3. Get the issuer - fail fast for missing issuer
        Optional<String> issuer = decodedJwt.get().getIssuer();
        if (issuer.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM.format("iss"));
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            return Optional.empty();
        }

        // 4. Look up the issuer config - fail fast for unknown issuer
        IssuerConfig issuerConfig = issuerConfigMap.get(issuer.get());
        if (issuerConfig == null) {
            LOGGER.warn(JWTValidationLogMessages.WARN.NO_ISSUER_CONFIG.format(issuer.get()));
            securityEventCounter.increment(SecurityEventCounter.EventType.NO_ISSUER_CONFIG);
            return Optional.empty();
        }

        // 5. Validate header - create validator only if needed
        TokenHeaderValidator headerValidator = new TokenHeaderValidator(issuerConfig, securityEventCounter);
        if (!headerValidator.validate(decodedJwt.get())) {
            LOGGER.debug("Token header validation failed");
            return Optional.empty();
        }

        // 6. Validate signature - create validator only if needed
        // Initialize the JwksLoader if needed
        issuerConfig.initSecurityEventCounter(securityEventCounter);
        JwksLoader jwksLoader = issuerConfig.getJwksLoader();

        TokenSignatureValidator signatureValidator = new TokenSignatureValidator(jwksLoader, securityEventCounter);
        if (!signatureValidator.validateSignature(decodedJwt.get())) {
            LOGGER.debug("Token signature validation failed");
            return Optional.empty();
        }

        // 7. Build token - only if header and signature are valid
        Optional<T> token = tokenBuilder.apply(decodedJwt.get(), issuerConfig);
        if (token.isEmpty()) {
            LOGGER.debug("Token building failed");
            return Optional.empty();
        }

        // 8. Validate claims - create validator only if token is built successfully
        TokenClaimValidator claimValidator = new TokenClaimValidator(issuerConfig, securityEventCounter);
        @SuppressWarnings("unchecked")
        Optional<T> validatedToken = claimValidator.validate(token.get())
                .map(validatedContent -> (T) validatedContent);

        if (validatedToken.isEmpty()) {
            LOGGER.debug("Token claim validation failed");
        } else {
            LOGGER.debug("Token successfully validated");
        }

        return validatedToken;
    }

    /**
     * Functional interface for building tokens with issuer config.
     *
     * @param <T> the type of token to create
     */
    @FunctionalInterface
    private interface TokenBuilderFunction<T> {
        Optional<T> apply(DecodedJwt decodedJwt, IssuerConfig issuerConfig);
    }
}
