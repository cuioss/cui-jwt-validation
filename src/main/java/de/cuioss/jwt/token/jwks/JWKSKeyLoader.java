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

import de.cuioss.jwt.token.security.JwkKeyHandler;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.io.StringReader;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static de.cuioss.jwt.token.JWTTokenLogMessages.WARN;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from a string content.
 * <p>
 * This implementation is useful when the JWKS content is already available as a string.
 * <p>
 * This implementation supports cryptographic agility by handling multiple key types
 * and algorithms, including RSA, EC, and RSA-PSS.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.5: Cryptographic Agility}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 * 
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class JWKSKeyLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(JWKSKeyLoader.class);
    private static final String RSA_KEY_TYPE = "RSA";
    private static final String EC_KEY_TYPE = "EC";

    private final Map<String, KeyInfo> keyInfoMap;

    /**
     * Creates a new JWKSKeyLoader with the specified JWKS content.
     *
     * @param jwksContent the JWKS content as a string, must not be null
     */
    public JWKSKeyLoader(@NonNull String jwksContent) {
        keyInfoMap = parseJwks(jwksContent);
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
     * @param jwks the JSON Web Key Set object
     * @param result the map to store the extracted keys
     */
    private void parseJsonWebKeySet(JsonObject jwks, Map<String, KeyInfo> result) {
        // Check if this is a JWKS with a "keys" array or a single key
        if (jwks.containsKey("keys")) {
            parseStandardJwks(jwks, result);
        } else if (jwks.containsKey("kty")) {
            // This is a single key object
            processKey(jwks, result);
        } else {
            LOGGER.warn(WARN.JWKS_MISSING_KEYS::format);
        }
    }

    /**
     * Parse a standard JWKS with a "keys" array.
     *
     * @param jwks the JWKS object
     * @param result the map to store the extracted keys
     */
    private void parseStandardJwks(JsonObject jwks, Map<String, KeyInfo> result) {
        JsonArray keysArray = jwks.getJsonArray("keys");
        if (keysArray != null) {
            for (int i = 0; i < keysArray.size(); i++) {
                JsonObject jwk = keysArray.getJsonObject(i);
                processKey(jwk, result);
            }
        }
    }

    /**
     * Process a single JWK and add it to the result map.
     *
     * @param jwk the JWK object
     * @param result the map to store the extracted key
     */
    private void processKey(JsonObject jwk, Map<String, KeyInfo> result) {
        if (!jwk.containsKey("kty")) {
            LOGGER.warn(WARN.JWK_MISSING_KTY::format);
            return;
        }

        String kty = jwk.getString("kty");
        String kid = jwk.containsKey("kid") ? jwk.getString("kid") : "default-key-id";
        String alg = jwk.containsKey("alg") ? jwk.getString("alg") : null;

        try {
            if (RSA_KEY_TYPE.equals(kty)) {
                Key publicKey = JwkKeyHandler.parseRsaKey(jwk);
                // Determine algorithm if not specified
                if (alg == null) {
                    alg = "RS256"; // Default to RS256 if not specified
                }
                result.put(kid, new KeyInfo(publicKey, alg));
                LOGGER.debug("Parsed RSA key with ID: %s and algorithm: %s", kid, alg);
            } else if (EC_KEY_TYPE.equals(kty)) {
                Key publicKey = JwkKeyHandler.parseEcKey(jwk);
                // Determine algorithm if not specified
                if (alg == null) {
                    // Determine algorithm based on curve
                    String curve = jwk.getString("crv", "P-256");
                    alg = JwkKeyHandler.determineEcAlgorithm(curve);
                }
                result.put(kid, new KeyInfo(publicKey, alg));
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
