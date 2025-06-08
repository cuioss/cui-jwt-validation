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
package de.cuioss.jwt.quarkus.deployment;

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;

/**
 * Processor for the CUI JWT Quarkus extension.
 * <p>
 * This class handles the build-time processing for the extension, including
 * registering the feature and setting up any necessary build items.
 */
public class CuiJwtProcessor {

    /**
     * The feature name for the CUI JWT extension.
     */
    private static final String FEATURE = "cui-jwt";

    /**
     * Register the CUI JWT feature.
     *
     * @return A {@link FeatureBuildItem} for the CUI JWT feature
     */
    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    /**
     * Register the JWT validation configuration as a bean.
     *
     * @return A {@link AdditionalBeanBuildItem} for the JWT validation configuration
     */
    @BuildStep
    AdditionalBeanBuildItem registerConfigMapping() {
        return AdditionalBeanBuildItem.builder().addBeanClass(JwtValidationConfig.class).build();
    }

    /**
     * Register the JWT validation configuration for reflection.
     *
     * @return A {@link ReflectiveClassBuildItem} for the JWT validation configuration
     */
    @BuildStep
    ReflectiveClassBuildItem registerConfigForReflection() {
        return ReflectiveClassBuildItem.builder("de.cuioss.jwt.quarkus.config.JwtValidationConfig")
                .methods(true)
                .fields(true)
                .build();
    }
}
