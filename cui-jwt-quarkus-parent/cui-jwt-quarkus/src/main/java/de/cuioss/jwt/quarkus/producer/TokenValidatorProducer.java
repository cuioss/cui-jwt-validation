/**
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.quarkus.producer;

import de.cuioss.jwt.quarkus.config.DefaultConfig;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * CDI producer for {@link TokenValidator} instances.
 * <p>
 * This producer creates a properly configured TokenValidator based on the
 * configuration provided by {@link JwtValidationConfig}.
 * </p>
 * <p>
 * The producer performs validation at startup to fail fast if the configuration
 * is invalid.
 * </p>
 */
@ApplicationScoped
public class TokenValidatorProducer {

    private static final CuiLogger log = new CuiLogger(TokenValidatorProducer.class);

    @Inject
    @DefaultConfig
    JwtValidationConfig jwtValidationConfig;

    @Getter
    private TokenValidator tokenValidator;

    private final SecurityEventCounter securityEventCounter = new SecurityEventCounter();

    /**
     * Initializes the TokenValidator at startup.
     * This method validates the configuration and fails fast if it's invalid.
     */
    @PostConstruct
    void initialize() {
        log.info("Initializing TokenValidator");

        // Create parser config
        ParserConfig parserConfig = createParserConfig(jwtValidationConfig.parser());

        // Create issuer configs
        List<IssuerConfig> issuerConfigs = createIssuerConfigs(jwtValidationConfig.issuers());

        if (issuerConfigs.isEmpty()) {
            throw new IllegalStateException("No enabled issuers found in configuration");
        }

        // Initialize security event counter for each issuer config
        for (IssuerConfig issuerConfig : issuerConfigs) {
            issuerConfig.initSecurityEventCounter(securityEventCounter);
        }

        // Create TokenValidator
        tokenValidator = new TokenValidator(parserConfig, issuerConfigs.toArray(new IssuerConfig[0]));

        log.info("TokenValidator initialized with {} issuers", issuerConfigs.size());
    }

    /**
     * Produces a {@link TokenValidator} instance.
     *
     * @return the configured TokenValidator
     */
    @Produces
    @ApplicationScoped
    public TokenValidator produceTokenValidator() {
        return tokenValidator;
    }

    /**
     * Creates a list of IssuerConfig instances from the configuration map.
     *
     * @param issuersConfig the map of issuer configurations
     * @return a list of IssuerConfig instances
     */
    @SuppressWarnings("java:S3655") // owolff: False positive, already checked
    private List<IssuerConfig> createIssuerConfigs(Map<String, JwtValidationConfig.IssuerConfig> issuersConfig) {
        List<IssuerConfig> result = new ArrayList<>();

        for (Map.Entry<String, JwtValidationConfig.IssuerConfig> entry : issuersConfig.entrySet()) {
            String issuerName = entry.getKey();
            JwtValidationConfig.IssuerConfig issuerConfig = entry.getValue();

            // Skip disabled issuers
            if (!issuerConfig.enabled()) {
                log.info("Skipping disabled issuer: {}", issuerName);
                continue;
            }

            IssuerConfig.IssuerConfigBuilder builder = IssuerConfig.builder()
                    .issuer(issuerConfig.url());

            // Configure JWKS source
            if (issuerConfig.jwks().isPresent()) {
                JwtValidationConfig.HttpJwksLoaderConfig jwksConfig = issuerConfig.jwks().get();
                builder.httpJwksLoaderConfig(
                        HttpJwksLoaderConfig.builder()
                                .url(jwksConfig.url())
                                .refreshIntervalSeconds(jwksConfig.refreshIntervalSeconds())
                                .requestTimeoutSeconds(jwksConfig.readTimeoutMs() / 1000) // Convert ms to seconds
                                .build()
                );
            } else if (issuerConfig.publicKeyLocation().isPresent()) {
                builder.jwksFilePath(issuerConfig.publicKeyLocation().get());
            } else {
                throw new IllegalStateException("Issuer " + issuerName +
                        " has no JWKS configuration (jwks or publicKeyLocation)");
            }

            // Add audience if present in parser config
            if (issuerConfig.parser().isPresent()) {
                JwtValidationConfig.ParserConfig parserConfig = issuerConfig.parser().get();
                if (parserConfig.audience().isPresent()) {
                    builder.expectedAudience(parserConfig.audience().get());
                }
            }

            result.add(builder.build());
        }

        return result;
    }

    /**
     * Creates a ParserConfig from the configuration.
     *
     * @param parserConfig the parser configuration
     * @return a ParserConfig instance
     */
    private ParserConfig createParserConfig(JwtValidationConfig.ParserConfig parserConfig) {
        ParserConfig.ParserConfigBuilder builder = ParserConfig.builder()
                .maxTokenSize(parserConfig.maxTokenSizeBytes());

        return builder.build();
    }
}
