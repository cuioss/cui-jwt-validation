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
package de.cuioss.jwt.validation;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.valueobjects.junit5.contracts.ShouldImplementEqualsAndHashCode;
import de.cuioss.test.valueobjects.junit5.contracts.ShouldImplementToString;

/**
 * Tests for {@link IssuerConfig} verifying value object contracts.
 * <p>
 * Supports requirement CUI-JWT-1.2: Multi-Issuer Support.
 *
 * @author Oliver Wolff
 * @see <a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/specification/technical-components.adoc#multi-issuer">Multi-Issuer Specification</a>
 */
class IssuerConfigTest implements ShouldImplementToString<IssuerConfig>, ShouldImplementEqualsAndHashCode<IssuerConfig> {

    @Override
    public IssuerConfig getUnderTest() {
        return IssuerConfig.builder().issuer(Generators.nonBlankStrings().next()).build();
    }

}