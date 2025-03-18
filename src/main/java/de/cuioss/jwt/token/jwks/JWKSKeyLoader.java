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
import de.cuioss.tools.string.MoreStrings;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.security.Key;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from a string content.
 * <p>
 * This implementation is useful when the JWKS content is already available as a string.
 * 
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class JWKSKeyLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(JWKSKeyLoader.class);

    private final Map<String, Key> keyMap;

    /**
     * Creates a new JWKSKeyLoader with the specified JWKS content.
     *
     * @param jwksContent the JWKS content as a string, must not be null
     */
    public JWKSKeyLoader(@NonNull String jwksContent) {
        keyMap = new JwksParser().parseJwks(jwksContent);
    }

    @Override
    public Optional<Key> getKey(String kid) {
        if (MoreStrings.isBlank(kid)) {
            LOGGER.debug("Key ID is null or empty");
            return Optional.empty();
        }

        return Optional.ofNullable(keyMap.get(kid));
    }

    @Override
    public Optional<Key> getFirstKey() {
        if (keyMap.isEmpty()) {
            return Optional.empty();
        }
        // Return the first key in the map
        return Optional.of(keyMap.values().iterator().next());
    }

    @Override
    public Set<String> keySet() {
        return keyMap.keySet();
    }
}
