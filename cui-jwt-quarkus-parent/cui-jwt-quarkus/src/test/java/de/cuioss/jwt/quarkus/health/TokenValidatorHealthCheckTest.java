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

import de.cuioss.jwt.quarkus.config.JwtTestProfile;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
class TokenValidatorHealthCheckTest {

    @Inject
    @Liveness
    TokenValidatorHealthCheck healthCheck;

    @Test
    @DisplayName("Health check bean should be injected and available")
    void testHealthCheckBeanIsInjected() {
        assertNotNull(healthCheck, "TokenValidatorHealthCheck should be injected");
    }

    @Test
    @DisplayName("Health check should return valid response with status")
    void testHealthCheckBeanIsUpOrDown() {
        HealthCheckResponse response = healthCheck.call();
        assertNotNull(response, "HealthCheckResponse should not be null");
        assertNotNull(response.getStatus(), "HealthCheckResponse status should not be null");
        // Should be UP or DOWN, but not null
        assertTrue(response.getStatus() == HealthCheckResponse.Status.UP ||
                   response.getStatus() == HealthCheckResponse.Status.DOWN,
                   "Health check status should be either UP or DOWN");
    }

    @Test
    @DisplayName("Health check should have correct name")
    void testHealthCheckName() {
        HealthCheckResponse response = healthCheck.call();
        assertEquals("jwt-validator", response.getName(), 
                    "Health check should have correct name");
    }

    @Nested
    @DisplayName("Tests with Valid Configuration (Guaranteed UP)")
    class ValidConfigurationTests {

        @QuarkusTest
        @TestProfile(ValidIssuersTestProfile.class)
        @EnableTestLogger
        static class ValidIssuersTest {

            @Inject
            @Liveness
            TokenValidatorHealthCheck healthCheck;

            @Test
            @DisplayName("Health check should be UP with valid issuer configuration")
            void testHealthCheckUp() {
                HealthCheckResponse response = healthCheck.call();
                
                assertEquals(HealthCheckResponse.Status.UP, response.getStatus(),
                            "Health check should be UP with valid issuer configuration");
                assertEquals("jwt-validator", response.getName(),
                            "Health check should have correct name");
            }

            @Test
            @DisplayName("Health check should include issuer count when UP")
            void testHealthCheckDataWhenUp() {
                HealthCheckResponse response = healthCheck.call();
                
                assertEquals(HealthCheckResponse.Status.UP, response.getStatus(),
                            "Health check should be UP with valid configuration");
                
                assertTrue(response.getData().isPresent(), 
                          "Health check data should be present when UP");
                
                Map<String, Object> data = response.getData().get();
                assertTrue(data.containsKey("issuerCount"), 
                          "Health check data should contain issuerCount");
                
                Object issuerCountValue = data.get("issuerCount");
                assertNotNull(issuerCountValue, "issuerCount should not be null");
                
                assertTrue(issuerCountValue instanceof Number, 
                          "issuerCount should be a Number, but was: " + issuerCountValue.getClass().getSimpleName());
                
                int issuerCount = ((Number) issuerCountValue).intValue();
                assertTrue(issuerCount > 0, 
                          "issuerCount should be greater than 0 when UP, but was: " + issuerCount);
            }
        }
    }

    /**
     * Test profile that ensures valid issuer configuration for guaranteed UP status.
     */
    public static class ValidIssuersTestProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            Map<String, String> config = new HashMap<>();
            // Disable default issuers and ensure we have at least one valid issuer
            config.put("cui.jwt.issuers.default.enabled", "false");
            config.put("cui.jwt.issuers.default.url", "https://disabled.example.com");
            
            config.put("cui.jwt.issuers.keycloak.enabled", "false");
            config.put("cui.jwt.issuers.keycloak.url", "https://disabled.example.com");
            
            config.put("cui.jwt.issuers.wellknown.enabled", "false");
            config.put("cui.jwt.issuers.wellknown.url", "https://disabled.example.com");
            
            config.put("cui.jwt.issuers.test-issuer.enabled", "false");
            config.put("cui.jwt.issuers.test-issuer.url", "https://disabled.example.com");
            
            // Configure a test issuer with all required properties
            config.put("cui.jwt.issuers.valid-test.enabled", "true");
            config.put("cui.jwt.issuers.valid-test.url", "https://example.com/auth");
            config.put("cui.jwt.issuers.valid-test.public-key-location", "classpath:keys/public_key.pem");
            
            return config;
        }
    }
}
