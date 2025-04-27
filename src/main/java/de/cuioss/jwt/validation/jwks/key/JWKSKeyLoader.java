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
package de.cuioss.jwt.validation.jwks.key;

import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoader;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

import java.io.StringReader;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from a string content.
 * <p>
 * This implementation is useful when the JWKS content is already available as a string.
 * <p>
 * This implementation supports cryptographic agility by handling multiple key types
 * and algorithms, including RSA, EC, and RSA-PSS.
 * <p>
 * The class stores the original JWKS content string and the ETag value from HTTP responses
 * to support content-based caching and HTTP 304 "Not Modified" handling in {@link HttpJwksLoader}.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.5: Cryptographic Agility}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 */
@ToString(of = {"keyInfoMap", "originalString", "etag"})
@EqualsAndHashCode(of = {"keyInfoMap", "originalString", "etag"})
public class JWKSKeyLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(JWKSKeyLoader.class);
    private static final String RSA_KEY_TYPE = "RSA";
    private static final String EC_KEY_TYPE = "EC";

    private final Map<String, KeyInfo> keyInfoMap;
    @Getter
    private final String originalString;
    @Getter
    private final String etag;

    /**
     * Creates a new JWKSKeyLoader with the specified JWKS content.
     *
     * @param jwksContent the JWKS content as a string, must not be null
     */
    public JWKSKeyLoader(@NonNull String jwksContent) {
        this(jwksContent, null);
    }

    /**
     * Creates a new JWKSKeyLoader with the specified JWKS content and ETag.
     *
     * @param jwksContent the JWKS content as a string, must not be null
     * @param etag        the ETag value from64EncodedContent the HTTP response, may be null
     */
    public JWKSKeyLoader(@NonNull String jwksContent, String etag) {
        this.originalString = jwksContent;
        this.etag = etag;
        keyInfoMap = parseJwks(jwksContent);
    }

    /**
     * Checks if this loader contains valid keys.
     *
     * @return true if the loader contains at least one valid key, false otherwise
     */
    public boolean isNotEmpty() {
        return !keyInfoMap.isEmpty();
    }

    /**
     * Parse JWKS content and extract keys.
     *
     * @param jwksContent the JWKS content as a string
     * @return a map of key IDs to key infos
     */
    private Map<String, KeyInfo> parseJwks(String jwksContent) {
        Map<String, KeyInfo> result = new ConcurrentHashMap<>();

        try (JsonReader reader = Json.createReader(new StringReader(jwksContent))) {
            JsonObject jwks = reader.readObject();
            parseJsonWebKeySet(jwks, result);
        } catch (Exception e) {
            // Handle invalid JSON format
            LOGGER.warn(e, WARN.JWKS_JSON_PARSE_FAILED.format(e.getMessage()));
        }

        return result;
    }

    /**
     * Parse a JSON Web Key Set object and extract keys.
     *
     * @param jwks   the JSON Web Key Set object
     * @param result the map to store the extracted keys
     */
    private void parseJsonWebKeySet(JsonObject jwks, Map<String, KeyInfo> result) {
        // Check if this is a JWKS with a "keys" array or a single key
        if (JwkKeyConstants.Keys.isPresent(jwks)) {
            parseKeysArray(jwks, result);
        } else if (JwkKeyConstants.KeyType.isPresent(jwks)) {
            // This is a single key object
            processSingleKey(jwks, result);
        } else {
            LOGGER.warn(WARN.JWKS_MISSING_KEYS::format);
        }
    }

    /**
     * Parse a standard JWKS with a "keys" array.
     *
     * @param jwks   the JWKS object
     * @param result the map to store the extracted keys
     */
    private void parseKeysArray(JsonObject jwks, Map<String, KeyInfo> result) {
        var keysArray = JwkKeyConstants.Keys.extract(jwks);
        if (keysArray.isPresent()) {
            for (int i = 0; i < keysArray.get().size(); i++) {
                JsonObject jwk = keysArray.get().getJsonObject(i);
                processSingleKey(jwk, result);
            }
        }
    }

    /**
     * Process a single JWK and add it to the result map.
     *
     * @param jwk    the JWK object
     * @param result the map to store the extracted key
     */
    private void processSingleKey(JsonObject jwk, Map<String, KeyInfo> result) {
        var keyType = JwkKeyConstants.KeyType.getString(jwk);
        if (keyType.isEmpty()) {
            LOGGER.warn(WARN.JWK_MISSING_KTY::format);
            return;
        }

        String kty = keyType.get();
        String kid = JwkKeyConstants.KeyId.from(jwk).orElse("default-key-id");
        try {
            if (RSA_KEY_TYPE.equals(kty)) {
                var publicKey = JwkKeyHandler.parseRsaKey(jwk);
                // Determine algorithm if not specified
                String alg = JwkKeyConstants.Algorithm.from(jwk).orElse("RS256");// Default to RS256 if not specified
                result.put(kid, new KeyInfo(publicKey, alg, kid));
                LOGGER.debug("Parsed RSA key with ID: %s and algorithm: %s", kid, alg);
            } else if (EC_KEY_TYPE.equals(kty)) {
                var publicKey = JwkKeyHandler.parseEcKey(jwk);
                // Determine algorithm if not specified
                var algOption = JwkKeyConstants.Algorithm.from(jwk);
                String alg = algOption.orElse(null);
                if (algOption.isEmpty()) {
                    // Determine algorithm based on curve
                    String curve = JwkKeyConstants.Curve.from(jwk).orElse("P-256");
                    alg = JwkKeyHandler.determineEcAlgorithm(curve);
                }
                result.put(kid, new KeyInfo(publicKey, alg, kid));
                LOGGER.debug("Parsed EC key with ID: %s and algorithm: %s", kid, alg);
            } else {
                LOGGER.debug("Unsupported key type: %s for key ID: %s", kty, kid);
            }
        } catch (Exception e) {
            LOGGER.warn(e, WARN.RSA_KEY_PARSE_FAILED.format(kid, e.getMessage()));
        }
    }

    @Override
    public Optional<KeyInfo> getKeyInfo(String kid) {
        if (MoreStrings.isBlank(kid)) {
            LOGGER.debug("Key ID is null or empty");
            return Optional.empty();
        }

        return Optional.ofNullable(keyInfoMap.get(kid));
    }

    @Override
    public Optional<KeyInfo> getFirstKeyInfo() {
        if (keyInfoMap.isEmpty()) {
            return Optional.empty();
        }
        // Return the first key info in the map
        return Optional.of(keyInfoMap.values().iterator().next());
    }

    @Override
    public List<KeyInfo> getAllKeyInfos() {
        return new ArrayList<>(keyInfoMap.values());
    }

    @Override
    public Set<String> keySet() {
        return keyInfoMap.keySet();
    }
}
