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

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.tools.logging.CuiLogger;
import lombok.experimental.UtilityClass;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Factory class for creating {@link IssuerConfig} instances from configuration properties.
 * <p>
 * This utility class converts the Quarkus configuration properties into the domain
 * model objects used by the JWT validation library.
 * </p>
 */
@UtilityClass
class IssuerConfigFactory {

    private static final CuiLogger log = new CuiLogger(IssuerConfigFactory.class);

    /**
     * Creates a list of IssuerConfig instances from the configuration map.
     *
     * @param issuersConfig the map of issuer configurations
     * @return a list of IssuerConfig instances
     * @throws IllegalStateException if an issuer has no JWKS configuration
     */
    @SuppressWarnings("java:S3655") // owolff: False Positive, isPresent is checked.
    List<IssuerConfig> createIssuerConfigs(Map<String, JwtValidationConfig.IssuerConfig> issuersConfig) {
        List<IssuerConfig> result = new ArrayList<>();

        for (Map.Entry<String, JwtValidationConfig.IssuerConfig> entry : issuersConfig.entrySet()) {
            String issuerName = entry.getKey();
            JwtValidationConfig.IssuerConfig issuerConfig = entry.getValue();

            // Skip disabled issuers
            if (!issuerConfig.enabled()) {
                log.info("Skipping disabled issuer: %s", issuerName);
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
}
