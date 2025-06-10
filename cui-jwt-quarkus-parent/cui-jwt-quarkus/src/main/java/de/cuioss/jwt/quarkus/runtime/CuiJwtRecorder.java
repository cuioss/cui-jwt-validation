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
package de.cuioss.jwt.quarkus.runtime;

import de.cuioss.jwt.quarkus.health.JwksEndpointHealthCheck;
import de.cuioss.jwt.quarkus.health.TokenValidatorHealthCheck;
import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.runtime.annotations.Recorder;

import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Recorder for the CUI JWT Quarkus extension.
 * <p>
 * This class handles runtime initialization tasks such as creating and
 * registering health checks.
 */
@Recorder
public class CuiJwtRecorder {

    /**
     * Creates a {@link JwksEndpointHealthCheck} instance and initializes its cache.
     *
     * @param beanContainer the bean container
     * @return a consumer that initializes the health check if enabled
     */
    public Consumer<Boolean> initializeJwksEndpointHealthCheck(BeanContainer beanContainer) {
        return enabled -> {
            if (enabled) {
                // We don't need to initialize the cache here as it's done in the constructor
                // and post-construct methods of the health check
            }
        };
    }

    /**
     * Produces a function that gets the {@link JwksEndpointHealthCheck} for health reporting.
     *
     * @param beanContainer the bean container
     * @return a function that returns a boolean indicating if the health check is enabled
     */
    public Function<Boolean, Boolean> produceJwksEndpointHealthCheck(BeanContainer beanContainer) {
        return enabled -> enabled;
    }

    /**
     * Produces a function that gets the {@link TokenValidatorHealthCheck} for health reporting.
     *
     * @param beanContainer the bean container
     * @return a function that returns a boolean indicating if the health check is enabled
     */
    public Function<Boolean, Boolean> produceTokenValidatorHealthCheck(BeanContainer beanContainer) {
        return enabled -> enabled;
    }
}
