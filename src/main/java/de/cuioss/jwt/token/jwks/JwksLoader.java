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

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Interface for loading JSON Web Keys (JWK) from a JWKS source.
 * <p>
 * Implementations can load keys from different sources like HTTP endpoints or files.
 * <p>
 * This interface supports cryptographic agility by providing methods to get keys
 * along with their algorithm information.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.5: Cryptographic Agility}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 * 
 * @author Oliver Wolff
 */
public interface JwksLoader {

    /**
     * Gets a key by its ID.
     *
     * @param kid the key ID
     * @return an Optional containing the key info if found, empty otherwise
     */
    Optional<KeyInfo> getKeyInfo(String kid);

    /**
     * Gets the first available key.
     *
     * @return an Optional containing the first key info if available, empty otherwise
     */
    Optional<KeyInfo> getFirstKeyInfo();

    /**
     * Gets all available keys with their algorithms.
     *
     * @return a List containing all available key infos
     */
    List<KeyInfo> getAllKeyInfos();

    /**
     * Gets the set of all available key IDs.
     *
     * @return a Set containing all available key IDs
     */
    Set<String> keySet();

}
