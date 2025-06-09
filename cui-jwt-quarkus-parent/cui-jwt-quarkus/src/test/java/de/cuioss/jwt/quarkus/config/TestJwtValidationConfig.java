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
package de.cuioss.jwt.quarkus.config;

import de.cuioss.jwt.quarkus.config.JwtValidationConfig.HttpJwksLoaderConfig;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig.IssuerConfig;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig.ParserConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Test implementation of {@link JwtValidationConfig} for unit tests.
 * This class provides a mock implementation with predefined values
 * that match the test expectations.
 */
@ApplicationScoped
public class TestJwtValidationConfig {

    /**
     * Produces a mock JwtValidationConfig for testing.
     *
     * @return A mock implementation of JwtValidationConfig
     */
    @Produces
    @ApplicationScoped
    @TestConfig
    public JwtValidationConfig createTestConfig() {
        return new TestJwtValidationConfigImpl();
    }

    /**
     * Konkrete Implementierung statt anonymer Klasse
     */
    static class TestJwtValidationConfigImpl implements JwtValidationConfig {
        @Override
        public Map<String, IssuerConfig> issuers() {
            Map<String, IssuerConfig> issuers = new HashMap<>();
            issuers.put("default", new DefaultIssuerConfigImpl());
            issuers.put("keycloak", new KeycloakIssuerConfigImpl());
            return issuers;
        }

        @Override
        public ParserConfig parser() {
            return new GlobalParserConfigImpl();
        }
    }

    /**
     * Default-Issuer-Konfiguration
     */
    static class DefaultIssuerConfigImpl implements IssuerConfig {
        @Override
        public String url() {
            return "https://example.com/auth";
        }

        @Override
        public Optional<String> publicKeyLocation() {
            return Optional.empty();
        }

        @Override
        public Optional<HttpJwksLoaderConfig> jwks() {
            return Optional.empty();
        }

        @Override
        public Optional<ParserConfig> parser() {
            return Optional.empty();
        }

        @Override
        public boolean enabled() {
            return true;
        }
    }

    /**
     * Keycloak-Issuer-Konfiguration
     */
    static class KeycloakIssuerConfigImpl implements IssuerConfig {
        @Override
        public String url() {
            return "https://keycloak.example.com/auth/realms/master";
        }

        @Override
        public Optional<String> publicKeyLocation() {
            return Optional.of("classpath:keys/public_key.pem");
        }

        @Override
        public Optional<HttpJwksLoaderConfig> jwks() {
            return Optional.of(new KeycloakJwksConfigImpl());
        }

        @Override
        public Optional<ParserConfig> parser() {
            return Optional.of(new KeycloakParserConfigImpl());
        }

        @Override
        public boolean enabled() {
            return true;
        }
    }

    /**
     * Keycloak JWKS-Konfiguration
     */
    static class KeycloakJwksConfigImpl implements HttpJwksLoaderConfig {
        @Override
        public String url() {
            return "https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs";
        }

        @Override
        public int cacheTtlSeconds() {
            return 7200;
        }

        @Override
        public int refreshIntervalSeconds() {
            return 600;
        }

        @Override
        public int connectionTimeoutMs() {
            return 3000;
        }

        @Override
        public int readTimeoutMs() {
            return 3000;
        }

        @Override
        public int maxRetries() {
            return 5;
        }

        @Override
        public boolean useSystemProxy() {
            return true;
        }
    }

    /**
     * Keycloak Parser-Konfiguration
     */
    static class KeycloakParserConfigImpl implements ParserConfig {
        @Override
        public Optional<String> audience() {
            return Optional.of("my-app");
        }

        @Override
        public int leewaySeconds() {
            return 60;
        }

        @Override
        public int maxTokenSizeBytes() {
            return 16384;
        }

        @Override
        public boolean validateNotBefore() {
            return false;
        }

        @Override
        public boolean validateExpiration() {
            return true;
        }

        @Override
        public boolean validateIssuedAt() {
            return true;
        }

        @Override
        public String allowedAlgorithms() {
            return "RS256,ES256";
        }
    }

    /**
     * Globale Parser-Konfiguration
     */
    static class GlobalParserConfigImpl implements ParserConfig {
        @Override
        public Optional<String> audience() {
            return Optional.empty();
        }

        @Override
        public int leewaySeconds() {
            return 30;
        }

        @Override
        public int maxTokenSizeBytes() {
            return 8192;
        }

        @Override
        public boolean validateNotBefore() {
            return true;
        }

        @Override
        public boolean validateExpiration() {
            return true;
        }

        @Override
        public boolean validateIssuedAt() {
            return false;
        }

        @Override
        public String allowedAlgorithms() {
            return "RS256,RS384,RS512,ES256,ES384,ES512";
        }
    }
}
