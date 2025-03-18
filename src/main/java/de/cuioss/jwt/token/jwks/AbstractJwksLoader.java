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
package de.cuioss.jwt.token.jwks;

import de.cuioss.tools.logging.CuiLogger;

import java.security.Key;
import java.util.Map;

/**
 * Abstract base class for JWKS loaders that provides common functionality.
 * This class uses delegation to JwksParser for parsing JWKS content.
 * 
 * @author Oliver Wolff
 */
public abstract class AbstractJwksLoader {

    protected static final CuiLogger LOGGER = new CuiLogger(AbstractJwksLoader.class);

    private final JwksParser jwksParser = new JwksParser();

    /**
     * Parse JWKS content and extract keys.
     * 
     * @param jwksContent the JWKS content as a string
     * @return a map of key IDs to keys
     */
    protected Map<String, Key> parseJwks(String jwksContent) {
        return jwksParser.parseJwks(jwksContent);
    }
}
