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
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;
import lombok.experimental.Delegate;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from in-memory data.
 * <p>
 * This implementation is useful for testing or when JWKS data is already available in memory.
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class InMemoryJwksLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(InMemoryJwksLoader.class);

    @Delegate
    private final JWKSKeyLoader delegate;


    /**
     * Creates a new InMemoryJwksLoader with the specified JWKS content.
     *
     * @param jwksContent the JWKS content as a string, must not be null
     */
    public InMemoryJwksLoader(@NonNull String jwksContent) {
        LOGGER.debug("Resolving key loader for in-memory JWKS data");
        LOGGER.debug("Successfully read JWKS from in-memory data");
        this.delegate = new JWKSKeyLoader(jwksContent);
        LOGGER.debug("Successfully loaded %s keys", delegate.keySet().size());
    }

    /**
     * Creates a new InMemoryJwksLoader with the specified JWKS data.
     *
     * @param jwksData the JWKS data as a byte array, must not be null
     */
    public InMemoryJwksLoader(byte @NonNull [] jwksData) {
        this(new String(jwksData.clone())); // Defensive copy and convert to string
    }
}
