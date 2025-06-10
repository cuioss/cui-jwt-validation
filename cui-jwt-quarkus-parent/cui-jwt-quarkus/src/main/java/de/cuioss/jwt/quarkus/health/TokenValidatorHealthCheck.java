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
package de.cuioss.jwt.quarkus.health;

import de.cuioss.jwt.quarkus.producer.TokenValidatorProducer;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

/**
 * Health check for TokenValidator functionality.
 * This class implements the SmallRye Health check interface to provide
 * liveness status for the JWT validation component.
 */
@ApplicationScoped
@Liveness // Marks this as a liveness check
public class TokenValidatorHealthCheck implements HealthCheck {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidatorHealthCheck.class);

    @Inject
    TokenValidatorProducer tokenValidatorProducer;

    @Override
    public HealthCheckResponse call() {
        try {
            // Get the TokenValidator from the producer
            TokenValidator tokenValidator = tokenValidatorProducer.getTokenValidator();
            if (tokenValidator == null) {
                return HealthCheckResponse.named("jwt-validator")
                        .down()
                        .withData("error", "TokenValidator not initialized")
                        .build();
            }
            // Get issuer configs from the producer (not from TokenValidator)
            var issuerConfigs = tokenValidatorProducer.getIssuerConfigs();
            if (issuerConfigs == null || issuerConfigs.isEmpty()) {
                return HealthCheckResponse.named("jwt-validator")
                        .down()
                        .withData("error", "No issuer configurations found")
                        .build();
            }
            var builder = HealthCheckResponse.named("jwt-validator").up();
            builder.withData("issuers.count", issuerConfigs.size());
            int i = 0;
            for (var config : issuerConfigs) {
                String prefix = "issuer." + i + ".";
                builder.withData(prefix + "issuer", config.getIssuer());
                if (config.getHttpJwksLoaderConfig() != null) {
                    builder.withData(prefix + "jwksType", "http");
                } else if (config.getJwksFilePath() != null) {
                    builder.withData(prefix + "jwksType", "file");
                } else if (config.getJwksContent() != null) {
                    builder.withData(prefix + "jwksType", "memory");
                } else {
                    builder.withData(prefix + "jwksType", "unknown");
                }
                i++;
            }
            return builder.build();
        } catch (Exception e) {
            LOGGER.warn(e, "Error checking TokenValidator health: %s", e.getMessage());
            return HealthCheckResponse.named("jwt-validator")
                    .down()
                    .withData("error", e.getMessage())
                    .build();
        }
    }
}
