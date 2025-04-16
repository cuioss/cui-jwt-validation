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

import de.cuioss.jwt.token.domain.token.AccessTokenContent;
import de.cuioss.jwt.token.domain.token.IdTokenContent;
import de.cuioss.jwt.token.domain.token.RefreshTokenContent;
import de.cuioss.jwt.token.domain.token.TokenContent;
import de.cuioss.jwt.token.flow.DecodedJwt;
import de.cuioss.jwt.token.flow.IssuerConfig;
import de.cuioss.jwt.token.flow.NonValidatingJwtParser;
import de.cuioss.jwt.token.flow.TokenBuilder;
import de.cuioss.jwt.token.flow.TokenClaimValidator;
import de.cuioss.jwt.token.flow.TokenFactoryConfig;
import de.cuioss.jwt.token.flow.TokenHeaderValidator;
import de.cuioss.jwt.token.flow.TokenSignatureValidator;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.Builder;
import lombok.NonNull;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * Factory for creating and validating OAuth2/OpenID Connect tokens with multi-issuer support.
 * This implementation uses the elements of the package de.cuioss.jwt.token.flow for token
 * transformation and validation.
 * <p>
 * Key features:
 * <ul>
 *   <li>Support for multiple token issuers</li>
 *   <li>Pipeline-based token validation</li>
 *   <li>Creation of typed token instances ({@link AccessTokenContent}, {@link IdTokenContent}, {@link RefreshTokenContent})</li>
 *   <li>Thread-safe token creation and validation</li>
 *   <li>Configurable token size limits</li>
 * </ul>
 */
public class TokenFactory {

    private static final CuiLogger LOGGER = new CuiLogger(TokenFactory.class);

    private final NonValidatingJwtParser jwtParser;
    private final Map<String, IssuerConfig> issuerConfigMap;

    /**
     * Creates a new TokenFactory with the given issuer configurations and optional factory configuration.
     *
     * @param issuerConfigs a collection of issuer configurations, must not be null
     * @param config optional configuration for the factory, if null, default configuration will be used
     */
    @Builder
    public TokenFactory(@NonNull Collection<IssuerConfig> issuerConfigs, TokenFactoryConfig config) {
        TokenFactoryConfig config1 = config != null ? config : TokenFactoryConfig.builder().build();

        // Initialize NonValidatingJwtParser with configuration
        this.jwtParser = NonValidatingJwtParser.builder()
                .maxTokenSize(config1.getMaxTokenSize())
                .maxPayloadSize(config1.getMaxPayloadSize())
                .logWarningsOnDecodeFailure(config1.isLogWarningsOnDecodeFailure())
                .build();

        // Initialize issuerConfigMap with issuers as keys
        this.issuerConfigMap = new HashMap<>();
        for (IssuerConfig issuerConfig : issuerConfigs) {
            issuerConfigMap.put(issuerConfig.getIssuer(), issuerConfig);
        }

        LOGGER.debug("Created TokenFactory with %d issuer configurations", issuerConfigs.size());
    }

    /**
     * Creates an access token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed access token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<AccessTokenContent> createAccessToken(@NonNull String tokenString) {
        LOGGER.debug("Creating access token");
        return processTokenPipeline(
            tokenString,
            decodedJwt -> new TokenBuilder().createAccessToken(decodedJwt)
        );
    }

    /**
     * Creates an ID token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed ID token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<IdTokenContent> createIdToken(@NonNull String tokenString) {
        LOGGER.debug("Creating ID token");
        return processTokenPipeline(
            tokenString,
            decodedJwt -> new TokenBuilder().createIdToken(decodedJwt)
        );
    }

    /**
     * Creates a refresh token from the given token string.
     *
     * @param tokenString The token string to parse, must not be null
     * @return The parsed refresh token, which may be empty if the token is invalid or no parser is found
     */
    public Optional<RefreshTokenContent> createRefreshToken(@NonNull String tokenString) {
        LOGGER.debug("Creating refresh token");
        // For refresh tokens, we don't need the full pipeline
        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }

        return new TokenBuilder().createRefreshToken(tokenString);
    }

    /**
     * Processes a token through the validation pipeline.
     * 
     * @param tokenString the token string to process
     * @param tokenBuilder function to build the token from the decoded JWT
     * @param <T> the type of token to create
     * @return an Optional containing the validated token, or empty if validation fails
     */
    private <T extends TokenContent> Optional<T> processTokenPipeline(
            String tokenString, 
            Function<DecodedJwt, Optional<T>> tokenBuilder) {

        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }

        // 1. Decode the token to get the issuer
        Optional<DecodedJwt> decodedJwt = jwtParser.decode(tokenString);
        if (decodedJwt.isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.FAILED_TO_DECODE_JWT::format);
            return Optional.empty();
        }

        // 2. Get the issuer from the decoded token
        Optional<String> issuer = decodedJwt.get().getIssuer();
        if (issuer.isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format("iss"));
            return Optional.empty();
        }

        // 3. Look up the issuer config
        IssuerConfig issuerConfig = issuerConfigMap.get(issuer.get());
        if (issuerConfig == null) {
            LOGGER.warn("No configuration found for issuer: {}", issuer.get());
            return Optional.empty();
        }

        // 4. Create validators
        TokenHeaderValidator headerValidator = new TokenHeaderValidator(issuerConfig);
        TokenSignatureValidator signatureValidator = new TokenSignatureValidator(issuerConfig.getJwksKeyLoader());
        TokenClaimValidator claimValidator = new TokenClaimValidator(issuerConfig);

        // 5. Execute pipeline
        if (!headerValidator.validate(decodedJwt.get())) {
            LOGGER.debug("Token header validation failed");
            return Optional.empty();
        }

        if (!signatureValidator.validateSignature(decodedJwt.get())) {
            LOGGER.debug("Token signature validation failed");
            return Optional.empty();
        }

        // 6. Build token
        Optional<T> token = tokenBuilder.apply(decodedJwt.get());
        if (token.isEmpty()) {
            LOGGER.debug("Token building failed");
            return Optional.empty();
        }

        // 7. Validate claims
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
}
