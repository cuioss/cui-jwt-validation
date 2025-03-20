/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.test.generator;

import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for JWKS (JSON Web Key Sets).
 * Generates a JWKS JSON string.
 * Can be configured in "default" or "alternative" mode.
 */
public class JWKSGenerator implements TypedGenerator<String> {

    private final boolean useAlternativeMode;

    /**
     * Constructor with default mode (false = default mode, true = alternative mode).
     *
     * @param useAlternativeMode whether to use alternative mode
     */
    public JWKSGenerator(boolean useAlternativeMode) {
        this.useAlternativeMode = useAlternativeMode;
    }

    /**
     * Constructor with default mode (false).
     */
    public JWKSGenerator() {
        this(false);
    }

    @Override
    public String next() {
        if (useAlternativeMode) {
            return JWKSFactory.createValidJwksWithKeyId(JWKSFactory.ALTERNATIVE_KEY_ID);
        } else {
            return JWKSFactory.createDefaultJwks();
        }
    }
}