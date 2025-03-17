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

import java.security.Key;
import java.util.Optional;

/**
 * Interface for loading JSON Web Keys (JWK) from a JWKS source.
 * <p>
 * Implementations can load keys from different sources like HTTP endpoints or files.
 * 
 * @author Oliver Wolff
 */
public interface JwksLoader {

    /**
     * Gets a key by its ID.
     *
     * @param kid the key ID
     * @return an Optional containing the key if found, empty otherwise
     */
    Optional<Key> getKey(String kid);

    /**
     * Gets the first available key.
     *
     * @return an Optional containing the first key if available, empty otherwise
     */
    Optional<Key> getFirstKey();

    /**
     * Refreshes the keys from the JWKS source.
     */
    void refreshKeys();

}
