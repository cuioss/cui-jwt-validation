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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

/**
 * Producer for the default configuration that applies the {@link DefaultConfig} qualifier
 * to the synthetic JwtValidationConfig bean created by Quarkus.
 */
@ApplicationScoped
public class DefaultJwtValidationConfigProducer {

    /**
     * Produces a JwtValidationConfig bean with the DefaultConfig qualifier.
     * This delegates to the synthetic bean created by Quarkus ConfigMapping.
     * 
     * @param config The synthetic JwtValidationConfig bean from Quarkus
     * @return The same config but with a DefaultConfig qualifier
     */
    @Produces
    @DefaultConfig
    @ApplicationScoped
    public JwtValidationConfig createDefaultConfig(JwtValidationConfig config) {
        return config;
    }
}
