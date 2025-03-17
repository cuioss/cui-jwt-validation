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

import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from a file.
 * 
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode(callSuper = false)
public class FileJwksLoader extends AbstractJwksLoader {

    private final Path jwksPath;
    private final Map<String, Key> keyMap = new ConcurrentHashMap<>();

    /**
     * Creates a new FileJwksLoader with the specified file path.
     *
     * @param filePath the path to the JWKS file
     */
    public FileJwksLoader(@NonNull String filePath) {
        this.jwksPath = Paths.get(filePath);
        refreshKeys();
    }

    @Override
    public Optional<Key> getKey(String kid) {
        if (kid == null) {
            LOGGER.debug("Key ID is null");
            return Optional.empty();
        }

        Key key = keyMap.get(kid);
        if (key == null) {
            LOGGER.debug("No key found with ID: %s, refreshing keys", kid);
            refreshKeys();
            key = keyMap.get(kid);
        }

        return Optional.ofNullable(key);
    }

    @Override
    public Optional<Key> getFirstKey() {
        if (keyMap.isEmpty()) {
            LOGGER.debug("No keys available, refreshing keys");
            refreshKeys();
        }

        if (keyMap.isEmpty()) {
            return Optional.empty();
        }

        // Return the first key in the map
        return Optional.of(keyMap.values().iterator().next());
    }

    @Override
    public void refreshKeys() {
        LOGGER.debug("Refreshing keys from JWKS file: %s", jwksPath);
        try {
            String jwksContent = new String(Files.readAllBytes(jwksPath));
            LOGGER.debug("Successfully read JWKS from file: %s", jwksPath);

            Map<String, Key> newKeys = parseJwks(jwksContent);
            if (!newKeys.isEmpty()) {
                // Only replace keys if we successfully parsed at least one key
                keyMap.clear();
                keyMap.putAll(newKeys);
            }
            LOGGER.debug("Successfully refreshed %s keys", keyMap.size());
        } catch (IOException e) {
            LOGGER.warn(e, "Failed to read JWKS from file: %s", jwksPath);
        }
    }

    @Override
    public void shutdown() {
        LOGGER.debug("Shutting down FileJwksLoader");
        keyMap.clear();
    }
}