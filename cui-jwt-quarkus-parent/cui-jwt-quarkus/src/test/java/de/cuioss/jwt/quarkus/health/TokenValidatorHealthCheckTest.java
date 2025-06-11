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
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
        assertNotNull(response.getStatus(), "Health check status should not be null");
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

    @Test
    @DisplayName("Health check should include issuer count when available")
    void testHealthCheckDataWhenAvailable() {
        HealthCheckResponse response = healthCheck.call();
        
        if (response.getStatus() == HealthCheckResponse.Status.UP) {
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
